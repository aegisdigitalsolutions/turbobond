"""End-to-end activation, exercised in dry-run so nothing touches the host."""

from __future__ import annotations

import pytest

from turbobond.config import AppConfig
from turbobond.links.model import LinkState
from turbobond.supervisor import Phase, Supervisor
from turbobond.util.cmd import audit_log


@pytest.fixture
async def supervisor(cfg: AppConfig):
    cfg.router.password = "router-secret"
    sup = Supervisor(cfg)
    yield sup
    await sup.deactivate()


class TestFullActivation:
    async def test_activation_reaches_a_running_state(self, supervisor: Supervisor) -> None:
        result = await supervisor.activate(install_dependencies=False)
        assert result["phase"] in ("active", "degraded"), result.get("error")
        assert supervisor.active
        assert "error" not in result

    async def test_every_stage_runs_in_order(self, supervisor: Supervisor) -> None:
        await supervisor.activate(install_dependencies=False)
        phases = [stage["phase"] for stage in supervisor.status()["stages"]]
        assert phases == [
            "preflight",
            "router",
            "links",
            "optimization",
            "routing",
            "bond",
            "transport",
            "sip",
            "lan",
            "selector",
        ]

    async def test_no_stage_hard_fails(self, supervisor: Supervisor) -> None:
        await supervisor.activate(install_dependencies=False)
        failed = [s for s in supervisor.status()["stages"] if not s["ok"]]
        assert failed == [], f"stages failed: {[s['phase'] for s in failed]}"

    async def test_configured_and_discovered_uplinks_both_join_the_bond(
        self, supervisor: Supervisor
    ) -> None:
        """Two uplinks come from the config; a third is found automatically."""

        await supervisor.activate(install_dependencies=False)
        status = supervisor.status()
        names = [link["name"] for link in status["links"]["links"]]
        assert names == ["wan1", "wan2", "wwan0"]
        assert status["aggregate"]["uplinks"] == 3
        assert all(link["state"] == LinkState.UP.value for link in status["links"]["links"])

    async def test_capacity_is_the_sum_of_the_uplinks(self, supervisor: Supervisor) -> None:
        """Aggregation is the point: the bond reports the summed capacity."""

        await supervisor.activate(install_dependencies=False)
        status = supervisor.status()
        per_link = sum(link["uplink_mbps"] for link in status["links"]["links"])
        assert status["aggregate"]["up_mbps"] == pytest.approx(per_link)
        assert status["aggregate"]["up_mbps"] > 150.0

    async def test_a_discovered_cellular_uplink_is_treated_as_metered(
        self, supervisor: Supervisor
    ) -> None:
        await supervisor.activate(install_dependencies=False)
        links = {link["name"]: link for link in supervisor.status()["links"]["links"]}
        assert links["wwan0"]["metered"] is True
        assert links["wan1"]["metered"] is False
        # Being metered costs scheduling weight but never membership.
        assert links["wwan0"]["state"] == LinkState.UP.value

    async def test_activation_is_repeatable(self, supervisor: Supervisor) -> None:
        first = await supervisor.activate(install_dependencies=False)
        second = await supervisor.activate(install_dependencies=False)
        assert first["phase"] == second["phase"]
        assert len(second["stages"]) == 10


class TestSubsystemsAfterActivation:
    @pytest.fixture(autouse=True)
    async def activated(self, supervisor: Supervisor):
        await supervisor.activate(install_dependencies=False)
        self.supervisor = supervisor

    def test_sip_rules_are_wide_open(self) -> None:
        sip = self.supervisor.status()["sip"]
        assert sip["applied"]
        assert sip["wide_open"]
        assert sip["rtp_range"] == "10000-65535"
        assert 5060 in sip["signalling_ports"]

    def test_sip_is_pinned_to_a_single_uplink(self) -> None:
        """A registration that flaps its source address gets dropped by SBCs."""

        sip_stage = next(s for s in self.supervisor.status()["stages"] if s["phase"] == "sip")
        assert sip_stage["data"]["pinned_to"]

    def test_policy_routing_gives_each_uplink_its_own_table(self) -> None:
        commands = [" ".join(entry["argv"]) for entry in audit_log(limit=1000)]
        assert any("ip rule add from 192.168.1.50 table" in cmd for cmd in commands)
        assert any("ip rule add from 192.168.2.50 table" in cmd for cmd in commands)

    def test_mptcp_endpoints_are_registered(self) -> None:
        commands = [" ".join(entry["argv"]) for entry in audit_log(limit=1000)]
        assert any("ip mptcp endpoint add" in cmd for cmd in commands)
        assert any("ip mptcp limits set subflows" in cmd for cmd in commands)

    def test_kernel_tuning_is_applied(self) -> None:
        commands = [" ".join(entry["argv"]) for entry in audit_log(limit=1000)]
        assert any("tcp_congestion_control=bbr" in cmd for cmd in commands)
        assert any("net.ipv4.ip_forward=1" in cmd for cmd in commands)

    def test_both_routes_are_present(self) -> None:
        routes = self.supervisor.status()["routes"]
        assert {r["name"] for r in routes["routes"]} == {"direct", "shadow"}

    def test_the_direct_route_is_active_by_default(self) -> None:
        assert self.supervisor.status()["routes"]["active"] == "direct"

    def test_lan_devices_are_marked_bonded(self) -> None:
        devices = self.supervisor.status()["devices"]
        assert devices["total"] > 0
        assert devices["bonded"] == devices["online"]

    def test_devices_are_merged_from_both_sources(self) -> None:
        """The router's client list and the kernel neighbour table."""

        sources = {d["source"] for d in self.supervisor.status()["devices"]["devices"]}
        assert "router" in sources

    def test_aggregation_mode_is_reported(self) -> None:
        status = self.supervisor.status()
        assert status["bond_mode"] in ("tunnel", "ecmp")


class TestLocalAggregationMode:
    async def test_without_a_concentrator_it_falls_back_to_ecmp(self, cfg: AppConfig) -> None:
        sup = Supervisor(cfg)
        try:
            await sup.activate(install_dependencies=False)
            bond = next(s for s in sup.status()["stages"] if s["phase"] == "bond")
            assert bond["data"]["mode"] == "ecmp"
            # Local mode cannot aggregate a single connection, and says so.
            assert bond["degraded"]
            assert "concentrator" in bond["data"]["note"]
        finally:
            await sup.deactivate()

    async def test_ecmp_route_is_weighted_by_link_quality(self, cfg: AppConfig) -> None:
        sup = Supervisor(cfg)
        try:
            await sup.activate(install_dependencies=False)
            commands = [" ".join(e["argv"]) for e in audit_log(limit=1000)]
            multipath = [c for c in commands if "route replace default table 100" in c and "nexthop" in c]
            assert multipath
            # One nexthop per usable uplink, each carrying its own weight.
            assert multipath[-1].count("nexthop") == 3
            assert multipath[-1].count("weight") == 3
        finally:
            await sup.deactivate()


class TestTunnelMode:
    async def test_a_configured_concentrator_enables_packet_bonding(self, cfg: AppConfig) -> None:
        cfg.concentrator.enabled = True
        cfg.concentrator.host = "concentrator.example.com"
        sup = Supervisor(cfg)
        try:
            await sup.activate(install_dependencies=False)
            status = sup.status()
            assert status["bond_mode"] == "tunnel"
            assert status["tunnel"]["running"]
            # Every uplink gets its own socket, which is what spreads a single
            # connection's packets across all of them.
            assert len(status["tunnel"]["sockets"]) == 3
            assert all(sock["handshaken"] for sock in status["tunnel"]["sockets"])
        finally:
            await sup.deactivate()

    async def test_the_concentrator_route_bypasses_the_tunnel(self, cfg: AppConfig) -> None:
        """Otherwise the tunnel would try to carry the packets that build it."""

        cfg.concentrator.enabled = True
        cfg.concentrator.host = "203.0.113.10"
        sup = Supervisor(cfg)
        try:
            await sup.activate(install_dependencies=False)
            commands = [" ".join(e["argv"]) for e in audit_log(limit=1000)]
            assert any("route replace 203.0.113.10/32" in cmd for cmd in commands)
        finally:
            await sup.deactivate()


class TestFailureHandling:
    async def test_activation_fails_cleanly_with_no_uplinks(self, cfg: AppConfig) -> None:
        cfg.links = []
        cfg.auto_discover_links = False
        sup = Supervisor(cfg)
        result = await sup.activate(install_dependencies=False)
        assert result["phase"] == "failed"
        assert result["error"]["message"]
        assert result["error"]["remedy"]

    async def test_an_unreachable_router_degrades_rather_than_blocks(self, cfg: AppConfig) -> None:
        cfg.router.manage = False
        sup = Supervisor(cfg)
        try:
            result = await sup.activate(install_dependencies=False)
            assert result["phase"] in ("active", "degraded")
        finally:
            await sup.deactivate()

    async def test_shadow_route_without_a_server_degrades(self, cfg: AppConfig) -> None:
        sup = Supervisor(cfg)
        try:
            await sup.activate(install_dependencies=False)
            transport = next(s for s in sup.status()["stages"] if s["phase"] == "transport")
            assert transport["ok"]
            assert transport["degraded"]
        finally:
            await sup.deactivate()


class TestDeactivation:
    async def test_deactivation_removes_what_it_installed(self, cfg: AppConfig) -> None:
        sup = Supervisor(cfg)
        await sup.activate(install_dependencies=False)
        await sup.deactivate()

        assert sup.phase is Phase.IDLE
        assert not sup.active
        commands = [" ".join(e["argv"]) for e in audit_log(limit=2000)]
        assert any("nft delete table inet turbobond" in cmd for cmd in commands)
        assert any("ip mptcp endpoint flush" in cmd for cmd in commands)
        assert any("ip rule del" in cmd for cmd in commands)

    async def test_deactivating_twice_is_safe(self, cfg: AppConfig) -> None:
        sup = Supervisor(cfg)
        await sup.activate(install_dependencies=False)
        await sup.deactivate()
        await sup.deactivate()
        assert sup.phase is Phase.IDLE
