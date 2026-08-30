"""Firewalling for SIP and RTP.

In ``wide_open`` mode the SIP signalling ports and the whole RTP media range are
accepted unconditionally in both directions on input, output and forward, and
they are exempted from connection tracking. That is deliberately permissive: it
is what lets a handset behind carrier-grade NAT keep a registration alive and
receive an unsolicited inbound INVITE, which stateful filtering would otherwise
drop because there is no prior outbound flow to match.

The cost is real and worth stating: any host that can reach this gateway can
send packets to those ports. Everything *outside* the SIP and RTP ranges stays
behind the normal stateful policy, and ``sip.wide_open`` can be turned off to
fall back to conntrack-based SIP handling.

nftables is used where available, with an iptables fallback for older systems.
Both rule sets live in their own table/chain so they can be removed cleanly
without disturbing anything else on the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from turbobond.config import SipConfig
from turbobond.errors import FirewallError
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("sip.firewall")

NFT_TABLE = "turbobond"
IPT_CHAIN = "TURBOBOND_SIP"

Backend = Literal["nftables", "iptables", "none"]

# Conntrack helpers that rewrite SDP. These are the kernel's own SIP ALG and are
# the usual cause of one-way audio, so they are unloaded rather than tuned.
SIP_HELPER_MODULES = ("nf_nat_sip", "nf_conntrack_sip")


def backend_in_use() -> Backend:
    """Which firewall tool this host actually has."""

    if is_dry_run():
        return "nftables"
    if which("nft"):
        return "nftables"
    if which("iptables"):
        return "iptables"
    return "none"


@dataclass
class FirewallReport:
    backend: Backend = "none"
    applied: bool = False
    wide_open: bool = False
    signalling_ports: list[int] = field(default_factory=list)
    rtp_range: str = ""
    alg_disabled: bool = False
    helpers_unloaded: list[str] = field(default_factory=list)
    rules_installed: int = 0
    errors: list[str] = field(default_factory=list)
    ruleset: str = ""

    @property
    def ok(self) -> bool:
        return self.applied and not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "applied": self.applied,
            "wide_open": self.wide_open,
            "signalling_ports": self.signalling_ports,
            "rtp_range": self.rtp_range,
            "alg_disabled": self.alg_disabled,
            "helpers_unloaded": self.helpers_unloaded,
            "rules_installed": self.rules_installed,
            "errors": self.errors,
            "ok": self.ok,
        }


class SipFirewall:
    """Builds and applies the SIP/RTP firewall policy."""

    def __init__(self, cfg: SipConfig, *, lan_interface: str = "", tun_interface: str = "") -> None:
        self.cfg = cfg
        self.lan_interface = lan_interface
        self.tun_interface = tun_interface
        self.backend: Backend = backend_in_use()
        self.last_report = FirewallReport(backend=self.backend)

    # ------------------------------------------------------------- rule text

    @property
    def all_ports(self) -> list[int]:
        return sorted(set(self.cfg.signalling_ports) | set(self.cfg.tls_ports))

    @property
    def rtp_range(self) -> str:
        return f"{self.cfg.rtp_port_start}-{self.cfg.rtp_port_end}"

    def _port_set(self) -> str:
        return "{ " + ", ".join(str(p) for p in self.all_ports) + " }"

    def build_nft_ruleset(self) -> str:
        """The complete nftables table, applied atomically with `nft -f`."""

        cfg = self.cfg
        ports = self._port_set()
        rtp = f"{cfg.rtp_port_start}-{cfg.rtp_port_end}"
        lines: list[str] = [
            f"table inet {NFT_TABLE} {{",
            "",
            "  # SIP signalling ports, kept in a named set so they can be updated",
            "  # without reloading the whole ruleset.",
            "  set sip_ports {",
            "    type inet_service",
            "    flags interval",
            f"    elements = {ports}",
            "  }",
            "",
            "  set rtp_ports {",
            "    type inet_service",
            "    flags interval",
            f"    elements = {{ {rtp} }}",
            "  }",
            "",
        ]

        if cfg.wide_open and cfg.disable_conntrack_helper:
            # notrack must run in the raw hooks, before conntrack sees the packet.
            lines += [
                "  # Exempt voice traffic from connection tracking entirely. Without",
                "  # this, inbound INVITEs with no matching outbound flow are dropped",
                "  # and long-lived registrations expire out of the conntrack table.",
                "  chain raw_prerouting {",
                "    type filter hook prerouting priority raw; policy accept;",
                "    udp dport @sip_ports notrack",
                "    udp sport @sip_ports notrack",
                "    tcp dport @sip_ports notrack",
                "    tcp sport @sip_ports notrack",
                "    udp dport @rtp_ports notrack",
                "    udp sport @rtp_ports notrack",
                "  }",
                "",
                "  chain raw_output {",
                "    type filter hook output priority raw; policy accept;",
                "    udp dport @sip_ports notrack",
                "    udp sport @sip_ports notrack",
                "    tcp dport @sip_ports notrack",
                "    tcp sport @sip_ports notrack",
                "    udp dport @rtp_ports notrack",
                "    udp sport @rtp_ports notrack",
                "  }",
                "",
            ]

        accept_priority = "filter - 10"
        lines += [
            "  # Priority below the standard filter hook so these accepts are",
            "  # evaluated before any pre-existing DROP policy on the host.",
            "  chain input {",
            f"    type filter hook input priority {accept_priority}; policy accept;",
            *self._nft_accept_rules(),
            "  }",
            "",
            "  chain output {",
            f"    type filter hook output priority {accept_priority}; policy accept;",
            *self._nft_accept_rules(),
            "  }",
            "",
            "  chain forward {",
            f"    type filter hook forward priority {accept_priority}; policy accept;",
            *self._nft_accept_rules(),
            "  }",
            "",
            "  # Mark and prioritise voice so it wins every queue on the box.",
            "  chain mangle_output {",
            "    type route hook output priority mangle; policy accept;",
            f"    udp dport @rtp_ports ip dscp set {cfg.dscp_media}",
            f"    udp sport @rtp_ports ip dscp set {cfg.dscp_media}",
            f"    udp dport @sip_ports ip dscp set {cfg.dscp_signalling}",
            f"    tcp dport @sip_ports ip dscp set {cfg.dscp_signalling}",
            "  }",
            "",
            "  chain mangle_prerouting {",
            "    type filter hook prerouting priority mangle; policy accept;",
            f"    udp dport @rtp_ports ip dscp set {cfg.dscp_media}",
            f"    udp dport @sip_ports ip dscp set {cfg.dscp_signalling}",
            f"    tcp dport @sip_ports ip dscp set {cfg.dscp_signalling}",
            "  }",
            "}",
            "",
        ]
        return "\n".join(lines)

    def _nft_accept_rules(self) -> list[str]:
        """Accept rules shared by the input/output/forward chains."""

        if self.cfg.wide_open:
            return [
                "    udp dport @sip_ports accept",
                "    udp sport @sip_ports accept",
                "    tcp dport @sip_ports accept",
                "    tcp sport @sip_ports accept",
                "    udp dport @rtp_ports accept",
                "    udp sport @rtp_ports accept",
                # SIP over SCTP is rare but valid, and costs one rule to support.
                "    sctp dport @sip_ports accept",
                "    sctp sport @sip_ports accept",
                # ICMP unreachables are how a far end signals a dead media path.
                "    meta l4proto icmp icmp type { destination-unreachable, time-exceeded } accept",
            ]
        # Stateful mode: only replies and traffic we originated.
        return [
            "    ct state established,related accept",
            "    udp dport @sip_ports ct state new accept",
            "    tcp dport @sip_ports ct state new accept",
        ]

    def build_iptables_rules(self) -> list[list[str]]:
        """Equivalent policy for hosts without nftables."""

        cfg = self.cfg
        ports_csv = ",".join(str(p) for p in self.all_ports)
        rtp = f"{cfg.rtp_port_start}:{cfg.rtp_port_end}"
        rules: list[list[str]] = [
            ["iptables", "-N", IPT_CHAIN],
            ["iptables", "-F", IPT_CHAIN],
        ]

        if cfg.wide_open:
            for proto in ("udp", "tcp"):
                rules += [
                    ["iptables", "-A", IPT_CHAIN, "-p", proto, "-m", "multiport", "--dports", ports_csv, "-j", "ACCEPT"],
                    ["iptables", "-A", IPT_CHAIN, "-p", proto, "-m", "multiport", "--sports", ports_csv, "-j", "ACCEPT"],
                ]
            rules += [
                ["iptables", "-A", IPT_CHAIN, "-p", "udp", "--dport", rtp, "-j", "ACCEPT"],
                ["iptables", "-A", IPT_CHAIN, "-p", "udp", "--sport", rtp, "-j", "ACCEPT"],
                ["iptables", "-A", IPT_CHAIN, "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "ACCEPT"],
            ]
        else:
            rules += [
                ["iptables", "-A", IPT_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", IPT_CHAIN, "-p", "udp", "-m", "multiport", "--dports", ports_csv, "-j", "ACCEPT"],
            ]
        rules.append(["iptables", "-A", IPT_CHAIN, "-j", "RETURN"])

        # Hook the chain in at the top of each built-in chain.
        for builtin in ("INPUT", "OUTPUT", "FORWARD"):
            rules.append(["iptables", "-I", builtin, "1", "-j", IPT_CHAIN])

        if cfg.wide_open and cfg.disable_conntrack_helper:
            for proto in ("udp", "tcp"):
                rules += [
                    ["iptables", "-t", "raw", "-I", "PREROUTING", "1", "-p", proto,
                     "-m", "multiport", "--dports", ports_csv, "-j", "NOTRACK"],
                    ["iptables", "-t", "raw", "-I", "OUTPUT", "1", "-p", proto,
                     "-m", "multiport", "--dports", ports_csv, "-j", "NOTRACK"],
                ]
            rules += [
                ["iptables", "-t", "raw", "-I", "PREROUTING", "1", "-p", "udp", "--dport", rtp, "-j", "NOTRACK"],
                ["iptables", "-t", "raw", "-I", "OUTPUT", "1", "-p", "udp", "--dport", rtp, "-j", "NOTRACK"],
            ]

        rules += [
            ["iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", rtp,
             "-j", "DSCP", "--set-dscp", str(cfg.dscp_media)],
            ["iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp",
             "-m", "multiport", "--dports", ports_csv, "-j", "DSCP", "--set-dscp", str(cfg.dscp_signalling)],
        ]
        return rules

    # ---------------------------------------------------------------- applying

    def disable_kernel_alg(self) -> tuple[bool, list[str]]:
        """Turn off the kernel's SIP helper, which is an ALG in all but name."""

        unloaded: list[str] = []
        ok = True

        # Newer kernels gate helper auto-assignment behind this sysctl.
        result = run(
            ["sysctl", "-w", "net.netfilter.nf_conntrack_helper=0"],
            quiet=True,
            allow_missing=True,
        )
        if not (result.ok or result.skipped):
            ok = False

        for module in SIP_HELPER_MODULES:
            result = run(["modprobe", "-r", module], quiet=True, allow_missing=True)
            if result.ok or result.skipped:
                unloaded.append(module)

        if not is_dry_run():
            # Stop it coming back on the next boot.
            try:
                with open("/etc/modprobe.d/turbobond-sip.conf", "w") as fh:
                    fh.write(
                        "# Managed by turbobond: the SIP conntrack helper rewrites SDP bodies\n"
                        "# and breaks media negotiation, so it is blacklisted.\n"
                        + "".join(f"install {m} /bin/true\n" for m in SIP_HELPER_MODULES)
                    )
            except OSError as exc:
                log.debug("could not persist the SIP helper blacklist: %s", exc)

        log.info("kernel SIP helper disabled (unloaded: %s)", ", ".join(unloaded) or "none loaded")
        return ok, unloaded

    def apply(self) -> FirewallReport:
        """Install the policy. Idempotent."""

        report = FirewallReport(
            backend=self.backend,
            wide_open=self.cfg.wide_open,
            signalling_ports=self.all_ports,
            rtp_range=self.rtp_range,
        )
        if not self.cfg.enabled:
            report.errors.append("SIP handling is disabled in the configuration")
            self.last_report = report
            return report

        if self.cfg.disable_alg:
            report.alg_disabled, report.helpers_unloaded = self.disable_kernel_alg()

        if self.backend == "nftables":
            report.ruleset = self.build_nft_ruleset()
            self._flush_nft()
            result = run(["nft", "-f", "-"], input_text=report.ruleset, timeout=20, allow_missing=True)
            if result.ok or result.skipped:
                report.applied = True
                report.rules_installed = report.ruleset.count("accept") + report.ruleset.count("notrack")
            else:
                report.errors.append(f"nft rejected the ruleset: {result.stderr.strip()}")
        elif self.backend == "iptables":
            self._flush_iptables()
            failures = 0
            for rule in self.build_iptables_rules():
                result = run(rule, quiet=True, allow_missing=True)
                if result.ok or result.skipped:
                    report.rules_installed += 1
                elif "-N" not in rule:  # chain-already-exists is not a failure
                    failures += 1
            report.applied = report.rules_installed > 0
            if failures:
                report.errors.append(f"{failures} iptables rule(s) were rejected")
        else:
            report.errors.append("neither nft nor iptables is installed, so SIP rules were not applied")

        if report.applied:
            log.info(
                "SIP firewall active (%s, %s): ports %s, RTP %s",
                self.backend,
                "wide open" if self.cfg.wide_open else "stateful",
                ",".join(str(p) for p in self.all_ports),
                self.rtp_range,
            )
        else:
            log.warning("SIP firewall was not applied: %s", "; ".join(report.errors))

        self.last_report = report
        return report

    def _flush_nft(self) -> None:
        run(["nft", "delete", "table", "inet", NFT_TABLE], quiet=True, allow_missing=True)

    def _flush_iptables(self) -> None:
        for builtin in ("INPUT", "OUTPUT", "FORWARD"):
            # Remove any previous hook, ignoring "no such rule".
            for _ in range(4):
                result = run(["iptables", "-D", builtin, "-j", IPT_CHAIN], quiet=True, allow_missing=True)
                if not result.ok:
                    break
        run(["iptables", "-F", IPT_CHAIN], quiet=True, allow_missing=True)
        run(["iptables", "-X", IPT_CHAIN], quiet=True, allow_missing=True)

    def teardown(self) -> None:
        if self.backend == "nftables":
            self._flush_nft()
        elif self.backend == "iptables":
            self._flush_iptables()
        log.info("SIP firewall rules removed")

    # ------------------------------------------------------------- inspection

    def verify(self) -> dict[str, Any]:
        """Read the live ruleset back so the UI can prove the rules are in place."""

        if is_dry_run():
            return {"present": True, "backend": self.backend, "detail": "dry-run"}
        if self.backend == "nftables":
            result = run(["nft", "list", "table", "inet", NFT_TABLE], quiet=True, allow_missing=True)
            present = result.ok and "sip_ports" in result.stdout
            return {
                "present": present,
                "backend": "nftables",
                "detail": result.stdout if present else result.stderr.strip(),
            }
        if self.backend == "iptables":
            result = run(["iptables", "-S", IPT_CHAIN], quiet=True, allow_missing=True)
            return {"present": result.ok, "backend": "iptables", "detail": result.stdout or result.stderr.strip()}
        return {"present": False, "backend": "none", "detail": "no firewall backend installed"}

    def require_backend(self) -> None:
        if self.backend == "none":
            raise FirewallError(
                "no firewall backend is available",
                remedy="Install nftables (preferred) or iptables, then re-run activation.",
            )
