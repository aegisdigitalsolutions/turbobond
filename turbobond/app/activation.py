"""Drives activation from the web app and streams progress to the browser.

The user signs in and this runs; there is no second button to press unless
``auto_activate_on_login`` has been turned off.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from turbobond.logging_setup import get_logger
from turbobond.supervisor import Phase, Supervisor

log = get_logger("app.activation")

MAX_EVENTS = 500


@dataclass
class ProgressEvent:
    seq: int
    ts: float
    phase: str
    message: str
    fraction: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "phase": self.phase,
            "message": self.message,
            "fraction": round(self.fraction, 3),
        }


@dataclass
class ActivationState:
    running: bool = False
    started_ts: float = 0.0
    finished_ts: float = 0.0
    fraction: float = 0.0
    phase: str = Phase.IDLE.value
    message: str = ""
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    events: list[ProgressEvent] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "phase": self.phase,
            "message": self.message,
            "fraction": round(self.fraction, 3),
            "started_ts": self.started_ts,
            "finished_ts": self.finished_ts,
            "elapsed_s": round((self.finished_ts or time.time()) - self.started_ts, 1) if self.started_ts else 0,
            "error": self.error,
            "events": [e.as_dict() for e in self.events[-60:]],
        }


class ActivationController:
    """Serialises activation runs and exposes their progress."""

    def __init__(self, supervisor: Supervisor) -> None:
        self.supervisor = supervisor
        self.state = ActivationState()
        self._task: asyncio.Task[None] | None = None
        self._seq = 0
        self._lock = asyncio.Lock()
        supervisor.on_progress = self._on_progress

    def _on_progress(self, phase: Phase, message: str, fraction: float) -> None:
        self._seq += 1
        event = ProgressEvent(seq=self._seq, ts=time.time(), phase=phase.value, message=message, fraction=fraction)
        self.state.events.append(event)
        if len(self.state.events) > MAX_EVENTS:
            del self.state.events[: len(self.state.events) - MAX_EVENTS]
        self.state.phase = phase.value
        self.state.message = message
        self.state.fraction = fraction

    async def start(self, *, install_dependencies: bool = True) -> ActivationState:
        """Kick off an activation in the background."""

        async with self._lock:
            if self.state.running:
                return self.state
            self.state = ActivationState(running=True, started_ts=time.time(), phase=Phase.PREFLIGHT.value)
            self._task = asyncio.create_task(self._run(install_dependencies), name="turbobond-activation")
            return self.state

    async def _run(self, install_dependencies: bool) -> None:
        try:
            result = await self.supervisor.activate(install_dependencies=install_dependencies)
            self.state.result = result
            self.state.error = result.get("error")
        except Exception as exc:
            log.exception("activation raised")
            self.state.error = {"code": "internal", "message": str(exc)}
        finally:
            self.state.running = False
            self.state.finished_ts = time.time()
            self.state.fraction = 1.0
            self.state.phase = self.supervisor.phase.value

    async def wait(self, timeout: float = 300.0) -> ActivationState:
        """Block until the current activation finishes."""

        if self._task is not None and not self._task.done():
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=timeout)
            except TimeoutError:
                log.warning("activation is still running after %.0fs", timeout)
        return self.state

    async def stop(self) -> dict[str, Any]:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            self.state.running = False
        return await self.supervisor.deactivate()

    def events_since(self, seq: int) -> list[dict[str, Any]]:
        return [e.as_dict() for e in self.state.events if e.seq > seq]
