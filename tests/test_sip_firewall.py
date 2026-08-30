from __future__ import annotations

import pytest

from turbobond.config import SipConfig
from turbobond.sip.firewall import NFT_TABLE, SipFirewall
from turbobond.sip.qos import apply_sip_qos
from turbobond.util.cmd import audit_log


@pytest.fixture
def wide_open() -> SipFirewall:
    return SipFirewall(SipConfig(wide_open=True))


@pytest.fixture
def stateful() -> SipFirewall:
    return SipFirewall(SipConfig(wide_open=False))


class TestWideOpenRuleset:
    def test_signalling_is_accepted_in_both_directions(self, wide_open: SipFirewall) -> None:
        """Inbound INVITEs have no prior outbound flow to match against."""

        ruleset = wide_open.build_nft_ruleset()
        assert "udp dport @sip_ports accept" in ruleset
        assert "udp sport @sip_ports accept" in ruleset
        assert "tcp dport @sip_ports accept" in ruleset
        assert "tcp sport @sip_ports accept" in ruleset

    def test_the_full_rtp_range_is_accepted(self, wide_open: SipFirewall) -> None:
        ruleset = wide_open.build_nft_ruleset()
        assert "10000-65535" in ruleset
        assert "udp dport @rtp_ports accept" in ruleset
        assert "udp sport @rtp_ports accept" in ruleset

    def test_rules_are_installed_on_all_three_hooks(self, wide_open: SipFirewall) -> None:
        """Input alone would not cover traffic forwarded for LAN handsets."""

        ruleset = wide_open.build_nft_ruleset()
        for hook in ("hook input", "hook output", "hook forward"):
            assert hook in ruleset

    def test_voice_traffic_bypasses_connection_tracking(self, wide_open: SipFirewall) -> None:
        ruleset = wide_open.build_nft_ruleset()
        assert "priority raw" in ruleset
        assert "udp dport @sip_ports notrack" in ruleset
        assert "udp dport @rtp_ports notrack" in ruleset

    def test_accepts_run_before_any_existing_drop_policy(self, wide_open: SipFirewall) -> None:
        assert "priority filter - 10" in wide_open.build_nft_ruleset()

    def test_icmp_errors_are_allowed_through(self, wide_open: SipFirewall) -> None:
        """A far end signals a dead media path with an ICMP unreachable."""

        assert "destination-unreachable" in wide_open.build_nft_ruleset()

    def test_sip_over_sctp_is_covered(self, wide_open: SipFirewall) -> None:
        assert "sctp dport @sip_ports accept" in wide_open.build_nft_ruleset()

    def test_the_ruleset_lives_in_its_own_table(self, wide_open: SipFirewall) -> None:
        """So it can be removed without disturbing anything else on the host."""

        assert wide_open.build_nft_ruleset().startswith(f"table inet {NFT_TABLE} {{")


class TestStatefulRuleset:
    def test_stateful_mode_requires_an_established_flow(self, stateful: SipFirewall) -> None:
        ruleset = stateful.build_nft_ruleset()
        assert "ct state established,related accept" in ruleset
        assert "udp sport @sip_ports accept" not in ruleset

    def test_stateful_mode_does_not_disable_conntrack(self, stateful: SipFirewall) -> None:
        assert "notrack" not in stateful.build_nft_ruleset()


class TestDscpMarking:
    def test_media_is_marked_ef_and_signalling_cs3(self) -> None:
        firewall = SipFirewall(SipConfig(dscp_media=46, dscp_signalling=24))
        ruleset = firewall.build_nft_ruleset()
        assert "udp dport @rtp_ports ip dscp set 46" in ruleset
        assert "udp dport @sip_ports ip dscp set 24" in ruleset

    def test_marking_happens_on_both_directions(self) -> None:
        ruleset = SipFirewall(SipConfig()).build_nft_ruleset()
        assert "hook output priority mangle" in ruleset
        assert "hook prerouting priority mangle" in ruleset


class TestCustomPorts:
    def test_custom_signalling_ports_appear_in_the_set(self) -> None:
        firewall = SipFirewall(SipConfig(signalling_ports=[5060, 5070], tls_ports=[5061]))
        ruleset = firewall.build_nft_ruleset()
        assert "elements = { 5060, 5061, 5070 }" in ruleset

    def test_a_narrowed_rtp_range_is_honoured(self) -> None:
        firewall = SipFirewall(SipConfig(rtp_port_start=16384, rtp_port_end=32767))
        assert "16384-32767" in firewall.build_nft_ruleset()
        assert firewall.rtp_range == "16384-32767"

    def test_all_ports_merges_and_sorts_signalling_and_tls(self) -> None:
        firewall = SipFirewall(SipConfig(signalling_ports=[5080, 5060], tls_ports=[5061, 5060]))
        assert firewall.all_ports == [5060, 5061, 5080]


class TestIptablesFallback:
    def test_wide_open_rules_cover_both_directions(self) -> None:
        firewall = SipFirewall(SipConfig(wide_open=True))
        rendered = [" ".join(rule) for rule in firewall.build_iptables_rules()]
        assert any("--dports" in rule and "ACCEPT" in rule for rule in rendered)
        assert any("--sports" in rule and "ACCEPT" in rule for rule in rendered)
        assert any("NOTRACK" in rule for rule in rendered)

    def test_the_chain_is_hooked_into_every_builtin(self) -> None:
        rendered = [" ".join(rule) for rule in SipFirewall(SipConfig()).build_iptables_rules()]
        for builtin in ("INPUT", "OUTPUT", "FORWARD"):
            assert any(f"-I {builtin} 1" in rule for rule in rendered)

    def test_rtp_uses_iptables_colon_range_syntax(self) -> None:
        firewall = SipFirewall(SipConfig(rtp_port_start=10000, rtp_port_end=20000))
        rendered = [" ".join(rule) for rule in firewall.build_iptables_rules()]
        assert any("10000:20000" in rule for rule in rendered)


class TestApplication:
    def test_apply_issues_an_atomic_nft_load(self, wide_open: SipFirewall) -> None:
        report = wide_open.apply()
        assert report.applied
        assert report.backend == "nftables"
        assert report.wide_open
        commands = [" ".join(entry["argv"]) for entry in audit_log()]
        assert any(cmd.startswith("nft -f") for cmd in commands)

    def test_apply_removes_the_kernel_sip_helper(self, wide_open: SipFirewall) -> None:
        """The conntrack SIP helper rewrites SDP and causes one-way audio."""

        report = wide_open.apply()
        assert report.alg_disabled
        commands = [" ".join(entry["argv"]) for entry in audit_log()]
        assert any("modprobe -r nf_conntrack_sip" in cmd for cmd in commands)
        assert any("nf_conntrack_helper=0" in cmd for cmd in commands)

    def test_apply_is_idempotent(self, wide_open: SipFirewall) -> None:
        """Re-activation must converge, not stack duplicate rules."""

        wide_open.apply()
        wide_open.apply()
        commands = [" ".join(entry["argv"]) for entry in audit_log()]
        assert sum(1 for cmd in commands if "delete table inet" in cmd) == 2

    def test_a_disabled_config_applies_nothing(self) -> None:
        report = SipFirewall(SipConfig(enabled=False)).apply()
        assert not report.applied
        assert report.errors

    def test_teardown_deletes_the_table(self, wide_open: SipFirewall) -> None:
        wide_open.apply()
        wide_open.teardown()
        commands = [" ".join(entry["argv"]) for entry in audit_log()]
        assert any(f"nft delete table inet {NFT_TABLE}" in cmd for cmd in commands)

    def test_report_serialises_for_the_dashboard(self, wide_open: SipFirewall) -> None:
        data = wide_open.apply().as_dict()
        assert data["wide_open"] is True
        assert data["rtp_range"] == "10000-65535"
        assert data["backend"] == "nftables"


class TestQos:
    def test_priority_qdisc_and_dscp_filters_are_installed(self) -> None:
        report = apply_sip_qos(["eth0", "eth1"], SipConfig())
        assert report.ok
        commands = [" ".join(entry["argv"]) for entry in audit_log()]
        assert any("qdisc replace dev eth0 root handle 1: prio bands 3" in cmd for cmd in commands)
        # DSCP 46 occupies the top six bits of the TOS byte: 46 << 2 == 0xb8.
        assert any("match ip tos 0xb8 0xfc" in cmd for cmd in commands)

    def test_no_interfaces_is_a_no_op(self) -> None:
        assert apply_sip_qos([], SipConfig()).interfaces == {}
