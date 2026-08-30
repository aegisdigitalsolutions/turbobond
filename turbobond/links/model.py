"""Runtime model of a single uplink."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LinkState(str, Enum):
    UNKNOWN = "unknown"
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    DISABLED = "disabled"


@dataclass(slots=True)
class LinkHealth:
    """Rolling health signal for one uplink."""

    rtt_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_pct: float = 0.0
    rx_mbps: float = 0.0
    tx_mbps: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_ok_ts: float = 0.0
    last_check_ts: float = 0.0
    error: str = ""

    # Exponentially weighted moving averages smooth out one-off spikes.
    _EWMA_ALPHA = 0.3

    def record_success(self, rtt_ms: float, jitter_ms: float, loss_pct: float) -> None:
        alpha = self._EWMA_ALPHA
        self.rtt_ms = rtt_ms if self.rtt_ms == 0 else (alpha * rtt_ms + (1 - alpha) * self.rtt_ms)
        self.jitter_ms = jitter_ms if self.jitter_ms == 0 else (alpha * jitter_ms + (1 - alpha) * self.jitter_ms)
        self.loss_pct = alpha * loss_pct + (1 - alpha) * self.loss_pct
        self.consecutive_failures = 0
        self.consecutive_successes += 1
        self.last_ok_ts = self.last_check_ts = time.time()
        self.error = ""

    def record_failure(self, error: str = "") -> None:
        self.consecutive_successes = 0
        self.consecutive_failures += 1
        self.loss_pct = min(100.0, self.loss_pct * 0.7 + 100.0 * 0.3)
        self.last_check_ts = time.time()
        if error:
            self.error = error

    def as_dict(self) -> dict[str, Any]:
        return {
            "rtt_ms": round(self.rtt_ms, 2),
            "jitter_ms": round(self.jitter_ms, 2),
            "loss_pct": round(self.loss_pct, 2),
            "rx_mbps": round(self.rx_mbps, 2),
            "tx_mbps": round(self.tx_mbps, 2),
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "last_ok_ts": self.last_ok_ts,
            "last_check_ts": self.last_check_ts,
            "error": self.error,
        }


@dataclass(slots=True)
class Link:
    """One WAN uplink participating in the bond."""

    name: str
    interface: str
    gateway: str = ""
    source_ip: str = ""
    weight: float = 1.0
    uplink_mbps: float = 0.0
    downlink_mbps: float = 0.0
    metered: bool = False
    enabled: bool = True
    table_id: int = 0
    link_id: int = 0
    state: LinkState = LinkState.UNKNOWN
    health: LinkHealth = field(default_factory=LinkHealth)
    # Set once the bonding tunnel has a live socket bound to this interface.
    tunnel_ready: bool = False

    @property
    def usable(self) -> bool:
        return self.enabled and self.state in (LinkState.UP, LinkState.DEGRADED)

    @property
    def healthy(self) -> bool:
        return self.enabled and self.state is LinkState.UP

    def effective_weight(self) -> float:
        """Scheduling weight adjusted for measured quality.

        Capacity dominates, then loss, then latency. A metered link is held back
        so it only absorbs traffic the unmetered links cannot.
        """

        if not self.usable:
            return 0.0
        base = self.weight
        if self.uplink_mbps > 0:
            base *= max(0.1, self.uplink_mbps / 10.0)
        loss_factor = max(0.05, 1.0 - (self.health.loss_pct / 100.0) ** 0.5)
        rtt = max(self.health.rtt_ms, 1.0)
        latency_factor = 1.0 / (1.0 + (rtt / 100.0))
        if self.metered:
            base *= 0.25
        if self.state is LinkState.DEGRADED:
            base *= 0.4
        return max(0.001, base * loss_factor * latency_factor)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "interface": self.interface,
            "gateway": self.gateway,
            "source_ip": self.source_ip,
            "weight": self.weight,
            "effective_weight": round(self.effective_weight(), 4),
            "uplink_mbps": self.uplink_mbps,
            "downlink_mbps": self.downlink_mbps,
            "metered": self.metered,
            "enabled": self.enabled,
            "table_id": self.table_id,
            "link_id": self.link_id,
            "state": self.state.value,
            "tunnel_ready": self.tunnel_ready,
            "health": self.health.as_dict(),
        }
