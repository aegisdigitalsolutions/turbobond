"""Chooses which uplink carries each outbound packet.

Three modes, all of which respect live link health:

``WEIGHTED``
    Deficit weighted round-robin on bytes. Over any window each link carries a
    share of the traffic proportional to its effective weight, which is what
    actually aggregates capacity.

``LOWEST_LATENCY``
    Everything on the fastest healthy link. Used for the SIP pin and as the
    degenerate case when only one link is usable.

``REDUNDANT``
    Send a copy down every link. Costs bandwidth, buys immunity to loss on any
    single uplink; used for signalling packets when ``duplicate_critical`` is on.

The deficit counters are what make this a real byte-fair scheduler rather than a
packet-count round-robin: a link's deficit grows by its share of every quantum
and is spent by the size of each packet it carries, so a link with half the
weight carries half the *bytes*, not half the packets.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from turbobond.links.model import Link
from turbobond.logging_setup import get_logger

log = get_logger("bond.scheduler")

# Bytes handed out per scheduling round. Roughly one MTU, so a single large
# packet never starves a low-weight link for long.
DEFAULT_QUANTUM = 1500


class SchedulerMode(str, Enum):
    WEIGHTED = "weighted"
    LOWEST_LATENCY = "lowest_latency"
    REDUNDANT = "redundant"


@dataclass(slots=True)
class LinkCounters:
    packets: int = 0
    bytes: int = 0
    deficit: float = 0.0
    drops: int = 0


@dataclass
class SchedulerStats:
    total_packets: int = 0
    total_bytes: int = 0
    duplicated_packets: int = 0
    dropped_packets: int = 0
    per_link: dict[int, LinkCounters] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duplicated_packets": self.duplicated_packets,
            "dropped_packets": self.dropped_packets,
            "per_link": {
                str(link_id): {"packets": c.packets, "bytes": c.bytes, "drops": c.drops}
                for link_id, c in self.per_link.items()
            },
        }


class BondScheduler:
    """Distributes packets across the bonded uplinks."""

    def __init__(
        self,
        links: list[Link],
        *,
        mode: SchedulerMode = SchedulerMode.WEIGHTED,
        quantum: int = DEFAULT_QUANTUM,
    ) -> None:
        self._links = list(links)
        self.mode = mode
        self.quantum = quantum
        self.stats = SchedulerStats()
        self._lock = threading.Lock()
        self._cursor = 0
        self._sync_counters()

    # ------------------------------------------------------------------ links

    def set_links(self, links: list[Link]) -> None:
        """Replace the link set, e.g. after a link goes down or comes back."""

        with self._lock:
            self._links = list(links)
            self._cursor = 0
            self._sync_counters()
        log.debug("scheduler now has %d usable link(s)", len(self.usable_links()))

    def _sync_counters(self) -> None:
        for link in self._links:
            self.stats.per_link.setdefault(link.link_id, LinkCounters())

    def usable_links(self) -> list[Link]:
        return [link for link in self._links if link.usable and link.tunnel_ready]

    def _candidates(self) -> list[Link]:
        """Links that can carry traffic right now.

        Prefers links whose tunnel socket is live; falls back to any usable link
        so packets still flow while the tunnel is still coming up.
        """

        ready = self.usable_links()
        if ready:
            return ready
        return [link for link in self._links if link.usable]

    # -------------------------------------------------------------- selection

    def select(self, packet_len: int, *, critical: bool = False) -> list[Link]:
        """Return the link(s) that should carry a packet of ``packet_len`` bytes.

        An empty list means there is nowhere to send it and the caller must drop.
        """

        with self._lock:
            candidates = self._candidates()
            if not candidates:
                self.stats.dropped_packets += 1
                return []

            if len(candidates) == 1:
                chosen = [candidates[0]]
            elif critical or self.mode is SchedulerMode.REDUNDANT:
                chosen = list(candidates)
            elif self.mode is SchedulerMode.LOWEST_LATENCY:
                chosen = [min(candidates, key=lambda link: max(link.health.rtt_ms, 0.01))]
            else:
                chosen = [self._weighted_pick(candidates, packet_len)]

            self.stats.total_packets += 1
            self.stats.total_bytes += packet_len
            if len(chosen) > 1:
                self.stats.duplicated_packets += 1
            for link in chosen:
                counters = self.stats.per_link.setdefault(link.link_id, LinkCounters())
                counters.packets += 1
                counters.bytes += packet_len
            return chosen

    def _weighted_pick(self, candidates: list[Link], packet_len: int) -> Link:
        """Deficit weighted round-robin.

        Each pass credits every candidate with ``quantum * share`` bytes, and the
        first link holding enough deficit to cover the packet wins. Because the
        credit is proportional to weight, the long-run byte split matches the
        weight split.
        """

        total_weight = sum(link.effective_weight() for link in candidates)
        if total_weight <= 0:
            return candidates[0]

        for _ in range(len(candidates) * 2 + 2):
            for offset in range(len(candidates)):
                index = (self._cursor + offset) % len(candidates)
                link = candidates[index]
                counters = self.stats.per_link.setdefault(link.link_id, LinkCounters())
                if counters.deficit >= packet_len:
                    counters.deficit -= packet_len
                    self._cursor = (index + 1) % len(candidates)
                    return link
            # Nobody could afford the packet: credit everyone and try again.
            for link in candidates:
                counters = self.stats.per_link.setdefault(link.link_id, LinkCounters())
                share = link.effective_weight() / total_weight
                counters.deficit += self.quantum * share * len(candidates)

        # Unreachable in practice; fall back to the highest-weight link.
        return max(candidates, key=lambda link: link.effective_weight())

    # ------------------------------------------------------------------ views

    def share_estimate(self) -> dict[str, float]:
        """Expected fraction of traffic per link, for the dashboard."""

        candidates = self._candidates()
        total = sum(link.effective_weight() for link in candidates)
        if total <= 0:
            return {}
        return {link.name: round(link.effective_weight() / total, 4) for link in candidates}

    def aggregate_capacity_mbps(self) -> tuple[float, float]:
        """Summed up/down capacity of the links currently in the bond."""

        candidates = self._candidates()
        return (
            round(sum(link.uplink_mbps for link in candidates), 2),
            round(sum(link.downlink_mbps for link in candidates), 2),
        )

    def snapshot(self) -> dict[str, Any]:
        up, down = self.aggregate_capacity_mbps()
        return {
            "mode": self.mode.value,
            "quantum": self.quantum,
            "links_in_bond": len(self._candidates()),
            "share_estimate": self.share_estimate(),
            "aggregate_up_mbps": up,
            "aggregate_down_mbps": down,
            "stats": self.stats.as_dict(),
        }


def is_critical_packet(packet: bytes, sip_ports: set[int]) -> bool:
    """True for SIP signalling, which we duplicate rather than balance.

    Parses just enough of the IPv4/IPv6 header to read the transport ports. A
    lost REGISTER or INVITE costs seconds of call setup, so paying a few extra
    bytes to send it down every link is a good trade; RTP is left alone because
    duplicating a continuous media stream would waste real bandwidth.
    """

    if len(packet) < 20:
        return False
    version = packet[0] >> 4

    if version == 4:
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl + 4:
            return False
        protocol = packet[9]
        offset = ihl
    elif version == 6:
        if len(packet) < 44:
            return False
        protocol = packet[6]
        offset = 40
    else:
        return False

    # TCP (6), UDP (17), SCTP (132) all start with source/destination ports.
    if protocol not in (6, 17, 132):
        return False
    src_port = int.from_bytes(packet[offset : offset + 2], "big")
    dst_port = int.from_bytes(packet[offset + 2 : offset + 4], "big")
    return src_port in sip_ports or dst_port in sip_ports
