from __future__ import annotations

import pytest
from helpers import make_link

from turbobond.config import AppConfig, LinkConfig
from turbobond.links.discovery import (
    _guess_metered,
    _is_excluded,
    _preference,
    discover_links,
    links_to_config,
    list_interfaces,
    read_routes,
)
from turbobond.links.model import Link, LinkHealth, LinkState
from turbobond.links.monitor import LinkMonitor


class TestEffectiveWeight:
    def test_an_unusable_link_has_no_weight(self) -> None:
        assert make_link("down", state=LinkState.DOWN).effective_weight() == 0.0

    def test_capacity_scales_the_weight(self) -> None:
        """Aggregation depends on a fatter link carrying proportionally more."""

        small = make_link("small", uplink_mbps=50)
        large = make_link("large", link_id=2, uplink_mbps=500)
        assert large.effective_weight() > small.effective_weight() * 5

    def test_loss_reduces_the_weight(self) -> None:
        clean = make_link("clean", uplink_mbps=100, loss_pct=0.0)
        lossy = make_link("lossy", link_id=2, uplink_mbps=100, loss_pct=50.0)
        assert lossy.effective_weight() < clean.effective_weight()

    def test_latency_reduces_the_weight(self) -> None:
        fast = make_link("fast", uplink_mbps=100, rtt_ms=10)
        slow = make_link("slow", link_id=2, uplink_mbps=100, rtt_ms=300)
        assert slow.effective_weight() < fast.effective_weight()

    def test_metered_links_are_held_back_at_equal_capacity(self) -> None:
        unmetered = make_link("wired", uplink_mbps=100)
        metered = make_link("cell", link_id=2, uplink_mbps=100, metered=True)
        assert metered.effective_weight() == pytest.approx(unmetered.effective_weight() * 0.25)

    def test_a_degraded_link_still_carries_some_traffic(self) -> None:
        """Degraded means 'use less of it', not 'stop using it'."""

        degraded = make_link("wobbly", uplink_mbps=100, state=LinkState.DEGRADED)
        assert 0 < degraded.effective_weight() < make_link("ok", uplink_mbps=100).effective_weight()

    def test_weight_is_never_zero_for_a_usable_link(self) -> None:
        awful = make_link("awful", uplink_mbps=0.1, loss_pct=99.0, rtt_ms=5000)
        assert awful.effective_weight() > 0


class TestLinkHealth:
    def test_success_smooths_measurements(self) -> None:
        health = LinkHealth()
        health.record_success(100.0, 5.0, 0.0)
        health.record_success(20.0, 1.0, 0.0)
        # An EWMA sits between the two samples rather than jumping to the latest.
        assert 20.0 < health.rtt_ms < 100.0

    def test_success_resets_the_failure_streak(self) -> None:
        health = LinkHealth()
        health.record_failure("timeout")
        health.record_failure("timeout")
        assert health.consecutive_failures == 2
        health.record_success(10.0, 1.0, 0.0)
        assert health.consecutive_failures == 0
        assert health.error == ""

    def test_failure_drives_loss_upward(self) -> None:
        health = LinkHealth()
        health.record_success(10.0, 1.0, 0.0)
        before = health.loss_pct
        health.record_failure("unreachable")
        assert health.loss_pct > before
        assert health.error == "unreachable"


class TestStateHelpers:
    def test_usable_covers_up_and_degraded(self) -> None:
        assert make_link("a", state=LinkState.UP).usable
        assert make_link("b", state=LinkState.DEGRADED).usable
        assert not make_link("c", state=LinkState.DOWN).usable
        assert not make_link("d", state=LinkState.DISABLED).usable

    def test_healthy_is_stricter_than_usable(self) -> None:
        degraded = make_link("b", state=LinkState.DEGRADED)
        assert degraded.usable
        assert not degraded.healthy

    def test_a_disabled_link_is_never_usable(self) -> None:
        link = make_link("x", state=LinkState.UP)
        link.enabled = False
        assert not link.usable


class TestInterfaceClassification:
    @pytest.mark.parametrize("name", ["lo", "docker0", "veth1234", "br-abc", "tbond0", "tun0", "wg0"])
    def test_virtual_interfaces_are_excluded(self, name: str) -> None:
        assert _is_excluded(name)

    @pytest.mark.parametrize("name", ["eth0", "enp3s0", "wlan0", "wwan0"])
    def test_real_interfaces_are_kept(self, name: str) -> None:
        assert not _is_excluded(name)

    def test_wired_is_preferred_over_wireless_and_cellular(self) -> None:
        assert _preference("eth0") > _preference("wlan0") > _preference("wwan0")

    @pytest.mark.parametrize("name", ["wwan0", "wwp0s1", "ppp0", "usb0"])
    def test_cellular_interfaces_are_assumed_metered(self, name: str) -> None:
        assert _guess_metered(name)

    def test_ethernet_is_not_assumed_metered(self) -> None:
        assert not _guess_metered("eth0")


class TestDiscovery:
    def test_configured_links_are_preserved_verbatim(self, cfg: AppConfig) -> None:
        links = discover_links(cfg)
        by_name = {link.name: link for link in links}
        assert by_name["wan1"].interface == "eth0"
        assert by_name["wan1"].weight == 3.0
        assert by_name["wan1"].gateway == "192.168.1.1"

    def test_autodiscovery_adds_uplinks_not_in_the_config(self, cfg: AppConfig) -> None:
        names = {link.name for link in discover_links(cfg)}
        assert "wwan0" in names

    def test_autodiscovery_can_be_turned_off(self, cfg: AppConfig) -> None:
        cfg.auto_discover_links = False
        assert {link.name for link in discover_links(cfg)} == {"wan1", "wan2"}

    def test_table_and_link_ids_are_unique(self, cfg: AppConfig) -> None:
        links = discover_links(cfg)
        assert len({link.table_id for link in links}) == len(links)
        assert len({link.link_id for link in links}) == len(links)
        assert all(link.table_id and link.link_id for link in links)

    def test_source_addresses_are_resolved(self, cfg: AppConfig) -> None:
        """Policy routing needs a source address per link to key its rule on."""

        assert all(link.source_ip for link in discover_links(cfg))

    def test_discovery_survives_an_empty_config(self) -> None:
        links = discover_links(AppConfig())
        assert links
        assert all(link.interface for link in links)

    def test_links_round_trip_back_into_config(self, cfg: AppConfig) -> None:
        links = discover_links(cfg)
        restored = links_to_config(links)
        assert [c.name for c in restored] == [link.name for link in links]
        assert all(isinstance(c, LinkConfig) for c in restored)

    def test_route_table_parsing_returns_defaults(self) -> None:
        defaults = [r for r in read_routes() if r["dst"] == "default"]
        assert defaults
        assert all(r.get("dev") for r in defaults)

    def test_interface_listing_excludes_virtual_devices(self) -> None:
        assert all(not _is_excluded(name) for name in list_interfaces())


class TestMonitor:
    async def test_probing_marks_reachable_links_up(self, links: list[Link]) -> None:
        monitor = LinkMonitor(links, interval_s=0.1)
        await monitor.probe_all()
        assert all(link.state is LinkState.UP for link in links)
        assert len(monitor.usable_links()) == 2

    async def test_a_disabled_link_is_marked_disabled(self, links: list[Link]) -> None:
        links[1].enabled = False
        monitor = LinkMonitor(links, interval_s=0.1)
        await monitor.probe_all()
        assert links[1].state is LinkState.DISABLED
        assert len(monitor.usable_links()) == 1

    async def test_state_changes_fire_the_callback(self, links: list[Link]) -> None:
        for link in links:
            link.state = LinkState.UNKNOWN
        seen: list[tuple[str, str, str]] = []
        monitor = LinkMonitor(
            links,
            interval_s=0.1,
            on_state_change=lambda link, old, new: seen.append((link.name, old.value, new.value)),
        )
        await monitor.probe_all()
        assert {entry[0] for entry in seen} == {"wan1", "wan2"}

    async def test_recovery_requires_sustained_success(self, links: list[Link]) -> None:
        """A flapping link must not be allowed to thrash the bond."""

        link = links[0]
        link.state = LinkState.DOWN
        link.health.consecutive_successes = 0
        monitor = LinkMonitor([link], interval_s=0.1)

        await monitor.probe_link(link)
        assert link.state is LinkState.DEGRADED
        for _ in range(3):
            await monitor.probe_link(link)
        assert link.state is LinkState.UP

    async def test_best_link_picks_the_highest_weight(self, links: list[Link]) -> None:
        monitor = LinkMonitor(links, interval_s=0.1)
        await monitor.probe_all()
        assert monitor.best_link() is links[0]

    async def test_snapshot_reports_aggregate_capacity(self, links: list[Link]) -> None:
        monitor = LinkMonitor(links, interval_s=0.1)
        await monitor.probe_all()
        snapshot = monitor.snapshot()
        assert snapshot["total"] == 2
        assert snapshot["usable"] == 2
        assert snapshot["aggregate_up_mbps"] == 150.0

    async def test_start_and_stop_are_clean(self, links: list[Link]) -> None:
        monitor = LinkMonitor(links, interval_s=0.05)
        await monitor.start()
        assert monitor.running
        await monitor.stop()
        assert not monitor.running

    def test_no_usable_links_yields_no_best_link(self) -> None:
        monitor = LinkMonitor([make_link("dead", state=LinkState.DOWN)])
        assert monitor.best_link() is None
