"""Subprocess execution with a global dry-run switch and a replayable audit log.

Every privileged action in turbobond goes through :func:`run`, which means the
whole system can be exercised (and tested) without touching the host by flipping
``dry_run``.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from turbobond.errors import DependencyError, PrivilegeError
from turbobond.logging_setup import get_logger

log = get_logger("cmd")

_state = threading.local()
_audit_lock = threading.Lock()
_audit: list[dict[str, Any]] = []
_MAX_AUDIT = 1000

_dry_run_global = False


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    skipped: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return (self.stdout or self.stderr).strip()


def set_dry_run(enabled: bool) -> None:
    """Enable/disable dry-run process-wide."""

    global _dry_run_global
    _dry_run_global = bool(enabled)
    log.info("dry-run mode %s", "enabled" if enabled else "disabled")


def is_dry_run() -> bool:
    return bool(getattr(_state, "dry_run", False)) or _dry_run_global


class dry_run_scope:
    """Context manager that forces dry-run for the current thread."""

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._previous = False

    def __enter__(self) -> dry_run_scope:
        self._previous = bool(getattr(_state, "dry_run", False))
        _state.dry_run = self._enabled
        return self

    def __exit__(self, *exc_info: object) -> None:
        _state.dry_run = self._previous


def audit_log(limit: int = 200) -> list[dict[str, Any]]:
    """Return the most recent commands turbobond issued."""

    with _audit_lock:
        return _audit[-limit:]


def clear_audit() -> None:
    with _audit_lock:
        _audit.clear()


def _record(entry: dict[str, Any]) -> None:
    with _audit_lock:
        _audit.append(entry)
        if len(_audit) > _MAX_AUDIT:
            del _audit[: len(_audit) - _MAX_AUDIT]


def which(binary: str) -> str | None:
    return shutil.which(binary)


def require(binary: str, *, package_hint: str = "") -> str:
    """Resolve a required executable or raise a :class:`DependencyError`."""

    path = which(binary)
    if path:
        return path
    hint = package_hint or binary
    raise DependencyError(
        f"required executable '{binary}' was not found on PATH",
        remedy=f"Install it (e.g. 'apt-get install -y {hint}') or run 'turbobond preflight --install'.",
    )


def run(
    argv: Sequence[str],
    *,
    check: bool = False,
    timeout: float = 30.0,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    quiet: bool = False,
    allow_missing: bool = False,
) -> CommandResult:
    """Execute ``argv``.

    In dry-run mode the command is recorded and a synthetic success is returned.
    ``check=True`` raises on a non-zero exit.
    """

    argv = [str(a) for a in argv]
    if not argv:
        raise ValueError("run() requires a non-empty argv")

    if is_dry_run():
        if not quiet:
            log.info("[dry-run] %s", " ".join(argv))
        _record({"ts": time.time(), "argv": argv, "rc": 0, "dry_run": True})
        return CommandResult(argv=argv, returncode=0, skipped=True)

    binary = which(argv[0])
    if binary is None:
        if allow_missing:
            log.debug("skipping missing command %s", argv[0])
            return CommandResult(argv=argv, returncode=127, stderr="not found", skipped=True)
        raise DependencyError(
            f"cannot run '{argv[0]}': executable not found",
            remedy="Run 'turbobond preflight --install' to install the missing tooling.",
        )
    argv[0] = binary

    start = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603 - argv is a list, never a shell string
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - start
        log.warning("command timed out after %.1fs: %s", duration, " ".join(argv))
        _record({"ts": time.time(), "argv": argv, "rc": -1, "timeout": True})
        result = CommandResult(argv=argv, returncode=-1, stderr=f"timeout after {timeout}s", duration_s=duration)
        if check:
            raise _to_error(result) from exc
        return result

    duration = time.perf_counter() - start
    result = CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        duration_s=duration,
    )
    if not quiet:
        level = log.debug if result.ok else log.warning
        level("%s -> rc=%s (%.0fms)", " ".join(argv), result.returncode, duration * 1000)
        if not result.ok and result.stderr.strip():
            log.warning("  stderr: %s", result.stderr.strip().splitlines()[0][:300])
    _record({"ts": time.time(), "argv": argv, "rc": result.returncode})

    if check and not result.ok:
        raise _to_error(result)
    return result


def _to_error(result: CommandResult) -> Exception:
    detail = (result.stderr or result.stdout).strip().splitlines()
    message = detail[0] if detail else f"exit code {result.returncode}"
    joined = " ".join(result.argv)
    if "operation not permitted" in message.lower() or "permission denied" in message.lower():
        return PrivilegeError(
            f"'{joined}' failed: {message}",
            remedy="turbobond needs root (or CAP_NET_ADMIN) to program routing and firewall state.",
        )
    return DependencyError(f"'{joined}' failed: {message}")


def run_all(commands: Sequence[Sequence[str]], *, check: bool = False, timeout: float = 30.0) -> list[CommandResult]:
    """Run a batch of commands, returning every result."""

    return [run(cmd, check=check, timeout=timeout) for cmd in commands]
