"""Continuous per-uplink health monitoring.

Each uplink is probed independently through its own interface so a dead link is
detected and removed from the bond within a couple of probe intervals, and comes
back automatically once it recovers.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from typing import Any

from turbobond.links.model import Link, LinkState
from turbobond.logging_setup import get_logger
from turbobond.util import netcheck

log = get_logger("links.monitor")

# How many consecutive results flip a link's state. Asymmetric on purpose:
# drop out fast, come back slowly, so a flapping link cannot thrash the bond.
FAIL_THRESHOLD = 2
DEGRADE_THRESHOLD = 1
RECOVER_THRESHOLD = 3

# Quality thresholds separating UP from DEGRADED.
DEGRADED_LOSS_PCT = 8.0
DEGRADED_RTT_MS = 400.0
DEGRADED_JITTER_MS = 80.0

StateCallback = Callable[[Link, LinkState, LinkState], None]


class LinkMonitor:
    """Probes every link on an interval and maintains their state machine."""

    def __init__(
        self,
        links: list[Link],
        *,
        targets: list[str] | None = None,
        interval_s: float = 5.0,
        probe_count: int = 3,
        on_state_change: StateCallback | None = None,
    ) -> None:
        self.links = links
        self.targets = targets or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.interval_s = interval_s
        self.probe_count = probe_count
        self.on_state_change = on_state_change
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._round = 0

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def probe_link(self, link: Link) -> None:
        """One probe cycle for a single link."""

        if not link.enabled:
            self._transition(link, LinkState.DISABLED)
            return

        result = await netcheck.probe_best(
            self.targets,
            interface=link.interface,
            count=self.probe_count,
            timeout_s=max(2.0, self.interval_s * 0.8),
        )

        if result.reachable:
            link.health.record_success(result.rtt_ms, result.jitter_ms, result.loss_pct)
        else:
            link.health.record_failure(result.error or "unreachable")

        rx, tx = await netcheck.measure_capacity_mbps(link.interface, duration_s=0.5)
        link.health.rx_mbps, link.health.tx_mbps = rx, tx
        # Observed throughput is a lower bound on capacity, never an upper one.
        if tx > link.uplink_mbps:
            link.uplink_mbps = tx
        if rx > link.downlink_mbps:
            link.downlink_mbps = rx

        self._transition(link, self._evaluate(link))

    def _evaluate(self, link: Link) -> LinkState:
        health = link.health
        if health.consecutive_failures >= FAIL_THRESHOLD:
            return LinkState.DOWN
        if health.consecutive_failures >= DEGRADE_THRESHOLD:
            return LinkState.DEGRADED
        if (
            health.loss_pct >= DEGRADED_LOSS_PCT
            or health.rtt_ms >= DEGRADED_RTT_MS
            or health.jitter_ms >= DEGRADED_JITTER_MS
        ):
            return LinkState.DEGRADED
        if link.state in (LinkState.DOWN, LinkState.UNKNOWN) and health.consecutive_successes < RECOVER_THRESHOLD:
            # Require sustained success before trusting a link with traffic again.
            return LinkState.DEGRADED if health.consecutive_successes else LinkState.DOWN
        return LinkState.UP

    def _transition(self, link: Link, new_state: LinkState) -> None:
        old_state = link.state
        if old_state is new_state:
            return
        link.state = new_state
        log.info(
            "link %s (%s): %s -> %s (rtt=%.0fms loss=%.1f%% jitter=%.0fms)",
            link.name,
            link.interface,
            old_state.value,
            new_state.value,
            link.health.rtt_ms,
            link.health.loss_pct,
            link.health.jitter_ms,
        )
        if self.on_state_change is not None:
            try:
                self.on_state_change(link, old_state, new_state)
            except Exception as exc:  # a bad callback must not stop monitoring
                log.warning("link state callback raised: %s", exc)

    async def probe_all(self) -> None:
        await asyncio.gather(*(self.probe_link(link) for link in self.links), return_exceptions=True)
        self._round += 1

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.probe_all()
            except Exception as exc:
                log.warning("monitor round failed: %s", exc)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_s)
                return

    async def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        # Seed initial state before returning so callers see real data immediately.
        await self.probe_all()
        self._task = asyncio.create_task(self._loop(), name="turbobond-link-monitor")
        log.info("link monitor started (%d link(s), every %.1fs)", len(self.links), self.interval_s)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        log.info("link monitor stopped")

    def usable_links(self) -> list[Link]:
        return [link for link in self.links if link.usable]

    def healthy_links(self) -> list[Link]:
        return [link for link in self.links if link.healthy]

    def best_link(self) -> Link | None:
        candidates = self.usable_links()
        if not candidates:
            return None
        return max(candidates, key=lambda link: link.effective_weight())

    def snapshot(self) -> dict[str, Any]:
        usable = self.usable_links()
        return {
            "round": self._round,
            "running": self.running,
            "interval_s": self.interval_s,
            "total": len(self.links),
            "usable": len(usable),
            "healthy": len(self.healthy_links()),
            "aggregate_up_mbps": round(sum(link.uplink_mbps for link in usable), 2),
            "aggregate_down_mbps": round(sum(link.downlink_mbps for link in usable), 2),
            "links": [link.as_dict() for link in self.links],
        }
