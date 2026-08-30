"""Active measurement of an uplink: reachability, RTT, jitter, loss, capacity."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import socket
import statistics
import time
from dataclasses import dataclass

from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("netcheck")

_PING_RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms")
_PING_LOSS = re.compile(r"([\d.]+)%\s*packet loss")


@dataclass(slots=True)
class ProbeResult:
    target: str
    interface: str = ""
    reachable: bool = False
    rtt_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_pct: float = 100.0
    samples: int = 0
    error: str = ""

    @property
    def score(self) -> float:
        """Higher is better. Combines latency, jitter and loss into one number."""

        if not self.reachable:
            return 0.0
        latency_term = 1.0 / max(self.rtt_ms, 1.0)
        loss_term = max(0.0, 1.0 - (self.loss_pct / 100.0)) ** 2
        jitter_term = 1.0 / (1.0 + (self.jitter_ms / 10.0))
        return latency_term * loss_term * jitter_term * 1000.0


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def ping(
    target: str,
    *,
    interface: str = "",
    count: int = 4,
    timeout_s: float = 4.0,
    interval_s: float = 0.25,
) -> ProbeResult:
    """ICMP probe, optionally bound to a specific interface."""

    result = ProbeResult(target=target, interface=interface)
    if is_dry_run():
        # Deterministic synthetic values keep dry-run activations self-consistent.
        result.reachable = True
        result.rtt_ms = 20.0
        result.jitter_ms = 2.0
        result.loss_pct = 0.0
        result.samples = count
        return result

    if which("ping") is None:
        return await tcp_probe(target, port=443, interface=interface, timeout_s=timeout_s)

    argv = ["ping", "-n", "-c", str(count), "-W", str(max(1, int(timeout_s))), "-i", str(interval_s)]
    if interface:
        argv += ["-I", interface]
    argv.append(target)

    proc = await asyncio.to_thread(run, argv, timeout=timeout_s + count * interval_s + 3, quiet=True, allow_missing=True)
    text = proc.stdout + proc.stderr
    rtts = [float(m) for m in _PING_RTT.findall(text)]
    loss_match = _PING_LOSS.search(text)

    result.samples = len(rtts)
    if loss_match:
        result.loss_pct = float(loss_match.group(1))
    if rtts:
        result.reachable = True
        result.rtt_ms = statistics.fmean(rtts)
        result.jitter_ms = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
    else:
        result.error = (proc.stderr or proc.stdout).strip().splitlines()[-1] if text.strip() else "no reply"
    return result


async def tcp_probe(
    target: str,
    *,
    port: int = 443,
    interface: str = "",
    source_ip: str = "",
    timeout_s: float = 4.0,
    count: int = 3,
) -> ProbeResult:
    """TCP handshake probe. Works where ICMP is filtered (most carrier networks)."""

    result = ProbeResult(target=target, interface=interface)
    if is_dry_run():
        result.reachable = True
        result.rtt_ms = 25.0
        result.loss_pct = 0.0
        result.samples = count
        return result

    rtts: list[float] = []
    failures = 0
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        try:
            if interface and hasattr(socket, "SO_BINDTODEVICE"):
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
            if source_ip:
                with contextlib.suppress(OSError):
                    sock.bind((source_ip, 0))
            start = time.perf_counter()
            await asyncio.to_thread(sock.connect, (target, port))
            rtts.append((time.perf_counter() - start) * 1000.0)
        except OSError as exc:
            failures += 1
            result.error = str(exc)
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    result.samples = len(rtts)
    result.loss_pct = (failures / count) * 100.0
    if rtts:
        result.reachable = True
        result.rtt_ms = statistics.fmean(rtts)
        result.jitter_ms = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
    return result


async def probe_best(
    targets: list[str],
    *,
    interface: str = "",
    count: int = 3,
    timeout_s: float = 4.0,
) -> ProbeResult:
    """Probe several targets concurrently and return the healthiest answer."""

    if not targets:
        return ProbeResult(target="", interface=interface, error="no probe targets configured")
    results = await asyncio.gather(
        *(ping(t, interface=interface, count=count, timeout_s=timeout_s) for t in targets),
        return_exceptions=True,
    )
    ok = [r for r in results if isinstance(r, ProbeResult)]
    if not ok:
        return ProbeResult(target=targets[0], interface=interface, error="all probes failed")
    return max(ok, key=lambda r: r.score)


async def measure_capacity_mbps(
    interface: str,
    *,
    duration_s: float = 1.0,
) -> tuple[float, float]:
    """Estimate current rx/tx throughput on ``interface`` from kernel counters.

    Returns ``(rx_mbps, tx_mbps)``. This measures *observed* traffic, which the
    scheduler uses as a floor for capacity when no explicit rate is configured.
    """

    if is_dry_run():
        return (0.0, 0.0)

    def _counters() -> tuple[int, int]:
        base = f"/sys/class/net/{interface}/statistics"
        try:
            with open(f"{base}/rx_bytes") as fh:
                rx = int(fh.read().strip())
            with open(f"{base}/tx_bytes") as fh:
                tx = int(fh.read().strip())
            return rx, tx
        except OSError:
            return (0, 0)

    rx0, tx0 = await asyncio.to_thread(_counters)
    await asyncio.sleep(duration_s)
    rx1, tx1 = await asyncio.to_thread(_counters)
    if rx0 == tx0 == 0 and rx1 == tx1 == 0:
        return (0.0, 0.0)
    rx_mbps = max(0.0, (rx1 - rx0) * 8 / 1e6 / duration_s)
    tx_mbps = max(0.0, (tx1 - tx0) * 8 / 1e6 / duration_s)
    return (rx_mbps, tx_mbps)


def interface_exists(interface: str) -> bool:
    import os

    return os.path.isdir(f"/sys/class/net/{interface}")


def interface_is_up(interface: str) -> bool:
    try:
        with open(f"/sys/class/net/{interface}/operstate") as fh:
            return fh.read().strip() in {"up", "unknown"}
    except OSError:
        return False
