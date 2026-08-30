from __future__ import annotations

from collections import Counter

from helpers import build_ipv4, build_ipv6, make_link

from turbobond.bond.scheduler import BondScheduler, SchedulerMode, is_critical_packet
from turbobond.links.model import LinkState


class TestWeightedDistribution:
    def test_bytes_follow_the_weight_ratio(self) -> None:
        """A 3:1 weight split should carry roughly a 3:1 byte split."""

        links = [
            make_link("fast", link_id=1, weight=3.0, rtt_ms=20.0),
            make_link("slow", link_id=2, weight=1.0, rtt_ms=20.0),
        ]
        scheduler = BondScheduler(links, mode=SchedulerMode.WEIGHTED)

        for _ in range(4000):
            chosen = scheduler.select(1000)
            assert len(chosen) == 1

        fast = scheduler.stats.per_link[1].bytes
        slow = scheduler.stats.per_link[2].bytes
        ratio = fast / slow
        assert 2.4 < ratio < 3.6, f"expected roughly 3:1, got {ratio:.2f}:1"

    def test_every_link_gets_used(self) -> None:
        links = [make_link(f"wan{i}", link_id=i, weight=1.0) for i in range(1, 5)]
        scheduler = BondScheduler(links)
        counts: Counter[str] = Counter()
        for _ in range(2000):
            for link in scheduler.select(1400):
                counts[link.name] += 1
        assert len(counts) == 4
        assert all(count > 300 for count in counts.values())

    def test_capacity_outweighs_a_nominal_weight(self) -> None:
        """A link with ten times the measured capacity should carry more."""

        links = [
            make_link("big", link_id=1, weight=1.0, uplink_mbps=500),
            make_link("small", link_id=2, weight=1.0, uplink_mbps=50),
        ]
        scheduler = BondScheduler(links)
        for _ in range(3000):
            scheduler.select(1000)
        assert scheduler.stats.per_link[1].bytes > scheduler.stats.per_link[2].bytes * 3

    def test_lossy_links_are_penalised(self) -> None:
        links = [
            make_link("clean", link_id=1, weight=1.0, loss_pct=0.0),
            make_link("lossy", link_id=2, weight=1.0, loss_pct=40.0),
        ]
        scheduler = BondScheduler(links)
        for _ in range(2000):
            scheduler.select(1000)
        assert scheduler.stats.per_link[1].bytes > scheduler.stats.per_link[2].bytes

    def test_metered_links_are_held_back(self) -> None:
        links = [
            make_link("unmetered", link_id=1, weight=1.0),
            make_link("metered", link_id=2, weight=1.0, metered=True),
        ]
        scheduler = BondScheduler(links)
        for _ in range(2000):
            scheduler.select(1000)
        assert scheduler.stats.per_link[1].bytes > scheduler.stats.per_link[2].bytes * 2


class TestLinkAvailability:
    def test_down_links_are_excluded(self) -> None:
        links = [
            make_link("up", link_id=1),
            make_link("down", link_id=2, state=LinkState.DOWN),
        ]
        scheduler = BondScheduler(links)
        for _ in range(200):
            chosen = scheduler.select(1000)
            assert [link.name for link in chosen] == ["up"]

    def test_no_usable_link_drops_the_packet(self) -> None:
        links = [make_link("down", link_id=1, state=LinkState.DOWN)]
        scheduler = BondScheduler(links)
        assert scheduler.select(1000) == []
        assert scheduler.stats.dropped_packets == 1

    def test_links_without_a_tunnel_still_carry_traffic(self) -> None:
        """Before the handshake completes we must not black-hole packets."""

        links = [make_link("wan", link_id=1, ready=False)]
        scheduler = BondScheduler(links)
        assert [link.name for link in scheduler.select(1000)] == ["wan"]

    def test_set_links_replaces_the_bond_membership(self) -> None:
        scheduler = BondScheduler([make_link("a", link_id=1)])
        scheduler.set_links([make_link("b", link_id=2), make_link("c", link_id=3)])
        names = {link.name for _ in range(50) for link in scheduler.select(500)}
        assert names == {"b", "c"}


class TestModes:
    def test_lowest_latency_mode_picks_the_fastest(self) -> None:
        links = [
            make_link("slow", link_id=1, rtt_ms=120.0),
            make_link("fast", link_id=2, rtt_ms=8.0),
        ]
        scheduler = BondScheduler(links, mode=SchedulerMode.LOWEST_LATENCY)
        for _ in range(50):
            assert [link.name for link in scheduler.select(500)] == ["fast"]

    def test_redundant_mode_uses_every_link(self, links) -> None:
        scheduler = BondScheduler(links, mode=SchedulerMode.REDUNDANT)
        chosen = scheduler.select(500)
        assert len(chosen) == len(links)
        assert scheduler.stats.duplicated_packets == 1

    def test_critical_packets_are_duplicated_in_weighted_mode(self, links) -> None:
        scheduler = BondScheduler(links, mode=SchedulerMode.WEIGHTED)
        assert len(scheduler.select(500, critical=True)) == len(links)


class TestShareEstimate:
    def test_shares_sum_to_one(self, links) -> None:
        scheduler = BondScheduler(links)
        shares = scheduler.share_estimate()
        assert set(shares) == {"wan1", "wan2"}
        assert abs(sum(shares.values()) - 1.0) < 0.01

    def test_aggregate_capacity_sums_the_links(self, links) -> None:
        scheduler = BondScheduler(links)
        up, down = scheduler.aggregate_capacity_mbps()
        assert up == 150.0
        assert down == 150.0


class TestCriticalPacketDetection:
    SIP_PORTS = {5060, 5061}

    def test_sip_destination_port_is_critical(self) -> None:
        assert is_critical_packet(build_ipv4(40000, 5060), self.SIP_PORTS)

    def test_sip_source_port_is_critical(self) -> None:
        assert is_critical_packet(build_ipv4(5060, 40000), self.SIP_PORTS)

    def test_sip_over_tcp_is_critical(self) -> None:
        assert is_critical_packet(build_ipv4(40000, 5061, protocol=6), self.SIP_PORTS)

    def test_rtp_is_not_duplicated(self) -> None:
        """Duplicating a continuous media stream would waste real bandwidth."""

        assert not is_critical_packet(build_ipv4(40000, 16384), self.SIP_PORTS)

    def test_ipv6_sip_is_critical(self) -> None:
        assert is_critical_packet(build_ipv6(40000, 5060), self.SIP_PORTS)

    def test_icmp_is_not_critical(self) -> None:
        assert not is_critical_packet(build_ipv4(0, 0, protocol=1), self.SIP_PORTS)

    def test_truncated_and_unknown_packets_are_safe(self) -> None:
        assert not is_critical_packet(b"", self.SIP_PORTS)
        assert not is_critical_packet(b"\x00" * 10, self.SIP_PORTS)
        assert not is_critical_packet(b"\xf0" + b"\x00" * 40, self.SIP_PORTS)
