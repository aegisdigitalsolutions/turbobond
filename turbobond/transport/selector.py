"""Picks which route is live and fails over between them automatically.

Both routes are kept warm, so a failover is a firewall-mark change rather than a
reconnect. The selector probes the active route continuously; after
``failover_after_failures`` consecutive bad probes it switches, and it will
switch back once the preferred route recovers and stays healthy.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from turbobond.config import RoutePolicy
from turbobond.logging_setup import get_logger
from turbobond.transport.profiles import ROUTES, RouteProfile, get_route, other_route
from turbobond.util import netcheck

log = get_logger("transport.selector")

# Consecutive healthy probes required before returning to the preferred route.
RECOVERY_THRESHOLD = 4


@dataclass
class RouteStatus:
    name: str
    available: bool = False
    healthy: bool = False
    active: bool = False
    rtt_ms: float = 0.0
    loss_pct: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_check_ts: float = 0.0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        profile = ROUTES.get(self.name)
        return {
            "name": self.name,
            "title": profile.title if profile else self.name,
            "available": self.available,
            "healthy": self.healthy,
            "active": self.active,
            "rtt_ms": round(self.rtt_ms, 2),
            "loss_pct": round(self.loss_pct, 2),
            "consecutive_failures": self.consecutive_failures,
            "last_check_ts": self.last_check_ts,
            "reason": self.reason,
        }


# Callback invoked when the active route changes: (old_name, new_name).
SwitchCallback = Callable[[str, str], Awaitable[None]]
# Returns whether a route's underlying machinery is up.
AvailabilityCheck = Callable[[str], Awaitable[tuple[bool, str]]]


@dataclass
class SelectorState:
    active: str = "direct"
    preferred: str = "direct"
    switches: int = 0
    last_switch_ts: float = 0.0
    statuses: dict[str, RouteStatus] = field(default_factory=dict)


class RouteSelector:
    """Health-checks both routes and keeps the best usable one active."""

    def __init__(
        self,
        policy: RoutePolicy,
        *,
        on_switch: SwitchCallback | None = None,
        availability: AvailabilityCheck | None = None,
    ) -> None:
        self.policy = policy
        self.on_switch = on_switch
        self.availability = availability
        self.state = SelectorState(active=policy.default_route, preferred=policy.default_route)
        for name in ROUTES:
            self.state.statuses[name] = RouteStatus(name=name, active=(name == policy.default_route))
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._switching = asyncio.Lock()

    # ------------------------------------------------------------------ views

    @property
    def active_route(self) -> RouteProfile:
        return get_route(self.state.active)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def status(self, name: str) -> RouteStatus:
        return self.state.statuses.setdefault(name, RouteStatus(name=name))

    # ----------------------------------------------------------------- probes

    async def check_route(self, name: str) -> RouteStatus:
        """Probe one route and update its status."""

        status = self.status(name)
        status.last_check_ts = time.time()

        if self.availability is not None:
            available, reason = await self.availability(name)
            status.available = available
            status.reason = reason
            if not available:
                status.healthy = False
                status.consecutive_successes = 0
                status.consecutive_failures += 1
                return status
        else:
            status.available = True

        probe = await netcheck.probe_best(self.policy.probe_targets, count=2, timeout_s=3.0)
        status.rtt_ms = probe.rtt_ms
        status.loss_pct = probe.loss_pct
        if probe.reachable and probe.loss_pct < 50.0:
            status.healthy = True
            status.consecutive_failures = 0
            status.consecutive_successes += 1
            status.reason = ""
        else:
            status.healthy = False
            status.consecutive_successes = 0
            status.consecutive_failures += 1
            status.reason = probe.error or "no reply from any probe target"
        return status

    async def check_all(self) -> dict[str, RouteStatus]:
        names = list(ROUTES)
        results = await asyncio.gather(*(self.check_route(n) for n in names), return_exceptions=True)
        for name, result in zip(names, results, strict=True):
            if isinstance(result, Exception):
                status = self.status(name)
                status.healthy = False
                status.reason = str(result)
        return self.state.statuses

    # -------------------------------------------------------------- switching

    async def switch_to(self, name: str, *, reason: str = "") -> bool:
        """Make ``name`` the active route."""

        if name not in ROUTES:
            log.warning("refusing to switch to unknown route %r", name)
            return False
        async with self._switching:
            previous = self.state.active
            if previous == name:
                return True
            status = self.status(name)
            if not status.available and self.availability is not None:
                log.warning("cannot switch to %s: %s", name, status.reason or "route is not available")
                return False

            if self.on_switch is not None:
                try:
                    await self.on_switch(previous, name)
                except Exception as exc:
                    log.error("route switch to %s failed: %s", name, exc)
                    return False

            self.state.active = name
            self.state.switches += 1
            self.state.last_switch_ts = time.time()
            for route_name, route_status in self.state.statuses.items():
                route_status.active = route_name == name
            log.info("active route: %s -> %s%s", previous, name, f" ({reason})" if reason else "")
            return True

    async def set_preferred(self, name: str) -> bool:
        """Change the route the selector returns to when everything is healthy."""

        if name not in ROUTES:
            return False
        self.state.preferred = name
        self.policy.default_route = name  # type: ignore[assignment]
        return await self.switch_to(name, reason="operator preference")

    async def evaluate(self) -> None:
        """One decision cycle."""

        await self.check_all()
        if not self.policy.auto_failover:
            return

        active = self.status(self.state.active)
        preferred = self.state.preferred

        if active.consecutive_failures >= self.policy.failover_after_failures:
            alternate = other_route(self.state.active)
            alt_status = self.status(alternate.name)
            if alt_status.available and alt_status.healthy:
                await self.switch_to(
                    alternate.name,
                    reason=f"{self.state.active} failed {active.consecutive_failures} probes",
                )
            else:
                log.warning(
                    "route %s is failing but %s is not usable either (%s)",
                    self.state.active,
                    alternate.name,
                    alt_status.reason or "unhealthy",
                )
            return

        if self.state.active != preferred:
            pref_status = self.status(preferred)
            if (
                pref_status.available
                and pref_status.healthy
                and pref_status.consecutive_successes >= RECOVERY_THRESHOLD
            ):
                await self.switch_to(preferred, reason="preferred route recovered")

    # -------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        await self.check_all()
        self._task = asyncio.create_task(self._loop(), name="turbobond-route-selector")
        log.info(
            "route selector started: preferred=%s, auto-failover=%s",
            self.state.preferred,
            self.policy.auto_failover,
        )

    async def _loop(self) -> None:
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self.policy.probe_interval_s)
                return
            try:
                await self.evaluate()
            except Exception as exc:
                log.warning("route evaluation failed: %s", exc)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "active": self.state.active,
            "preferred": self.state.preferred,
            "switches": self.state.switches,
            "last_switch_ts": self.state.last_switch_ts,
            "auto_failover": self.policy.auto_failover,
            "routes": [status.as_dict() for status in self.state.statuses.values()],
        }
