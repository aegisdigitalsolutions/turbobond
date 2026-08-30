"""Multipath TCP configuration.

MPTCP is the one form of true aggregation that needs no concentrator: the kernel
opens additional subflows over every uplink and the *remote peer* reassembles
them, provided that peer also speaks MPTCP. It cannot bond arbitrary traffic the
way the tunnel can, but it costs nothing to enable and it aggregates any flow
whose far end supports it.

turbobond enables MPTCP unconditionally and registers one endpoint per uplink,
so it layers underneath whichever route is active.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from turbobond.links.model import Link
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("bond.mptcp")


@dataclass(slots=True)
class MptcpState:
    available: bool = False
    enabled: bool = False
    endpoints: list[dict[str, Any]] | None = None
    max_subflows: int = 0
    max_add_addr_accepted: int = 0
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "enabled": self.enabled,
            "endpoints": self.endpoints or [],
            "max_subflows": self.max_subflows,
            "max_add_addr_accepted": self.max_add_addr_accepted,
            "error": self.error,
        }


def is_available() -> bool:
    """Whether this kernel exposes MPTCP at all (Linux 5.6+)."""

    if is_dry_run():
        return True
    import os

    return os.path.exists("/proc/sys/net/mptcp/enabled")


def enable() -> bool:
    result = run(["sysctl", "-w", "net.mptcp.enabled=1"], quiet=True, allow_missing=True)
    return result.ok or result.skipped


def _endpoint_flags(link: Link) -> list[str]:
    """A link is a `subflow` source; the best link is also `signal`ed to peers."""

    flags = ["subflow"]
    if link.metered:
        # Backup endpoints only carry traffic when the primaries are gone.
        flags.append("backup")
    return flags


def configure_endpoints(links: list[Link], *, limit_headroom: int = 2) -> MptcpState:
    """Register one MPTCP endpoint per uplink and raise the subflow limits."""

    state = MptcpState(available=is_available())
    if not state.available:
        state.error = "this kernel has no MPTCP support (needs Linux 5.6 or newer)"
        log.info("%s; skipping MPTCP setup", state.error)
        return state

    state.enabled = enable()
    if which("ip") is None and not is_dry_run():
        state.error = "iproute2 is not installed, so MPTCP endpoints cannot be registered"
        log.info(state.error)
        return state

    # Start clean so repeated activations do not accumulate stale endpoints.
    run(["ip", "mptcp", "endpoint", "flush"], quiet=True, allow_missing=True)

    usable = [link for link in links if link.usable and link.source_ip]
    for link in usable:
        argv = ["ip", "mptcp", "endpoint", "add", link.source_ip, "dev", link.interface]
        argv += _endpoint_flags(link)
        result = run(argv, quiet=True, allow_missing=True)
        if not (result.ok or result.skipped):
            log.debug("could not register MPTCP endpoint for %s: %s", link.name, result.stderr.strip())

    # Allow at least one subflow per uplink, plus headroom for peer-announced ones.
    limit = max(2, len(usable) + limit_headroom)
    state.max_subflows = limit
    state.max_add_addr_accepted = limit
    run(
        ["ip", "mptcp", "limits", "set", "subflows", str(limit), "add_addr_accepted", str(limit)],
        quiet=True,
        allow_missing=True,
    )

    state.endpoints = show_endpoints()
    log.info("MPTCP configured: %d endpoint(s), subflow limit %d", len(usable), limit)
    return state


def show_endpoints() -> list[dict[str, Any]]:
    if is_dry_run():
        return [{"address": "192.168.1.50", "dev": "eth0", "flags": ["subflow"]}]
    result = run(["ip", "-j", "mptcp", "endpoint", "show"], quiet=True, allow_missing=True)
    if result.ok and result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    result = run(["ip", "mptcp", "endpoint", "show"], quiet=True, allow_missing=True)
    return [{"raw": line.strip()} for line in result.stdout.splitlines() if line.strip()]


def flush() -> None:
    run(["ip", "mptcp", "endpoint", "flush"], quiet=True, allow_missing=True)


def state() -> MptcpState:
    st = MptcpState(available=is_available())
    if not st.available:
        return st
    result = run(["sysctl", "-n", "net.mptcp.enabled"], quiet=True, allow_missing=True)
    st.enabled = result.stdout.strip() == "1" or result.skipped
    st.endpoints = show_endpoints()
    return st
