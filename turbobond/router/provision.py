"""Applies the tuning profile to the router and to the local network stack.

The profile is named ``wrt-turbo-search`` and has two halves:

``turbo``
    Raise every throughput ceiling we control - congestion control, socket
    buffers, queue discipline, MTU/MSS, WMM, radio width, and the router's own
    power-saving/offload knobs.

``search``
    Continuously look for a better configuration: probe each uplink, re-rank
    them, and re-pin radio band/channel selections to whatever currently
    measures best.

A Nighthawk M7 Pro runs NETGEAR's own firmware, so this is applied through the
documented web-admin surface rather than by flashing third-party firmware.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from turbobond.config import OptimizationConfig
from turbobond.errors import RouterError
from turbobond.logging_setup import get_logger
from turbobond.router.base import RouterAdmin
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("router.provision")

# 5 GHz channels that are non-DFS in most regulatory domains, so the radio never
# has to vacate mid-call for radar detection.
NON_DFS_5GHZ = (36, 40, 44, 48, 149, 153, 157, 161, 165)


@dataclass(slots=True)
class ProvisionReport:
    router_settings: dict[str, bool] = field(default_factory=dict)
    sysctls: dict[str, bool] = field(default_factory=dict)
    qdisc: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(self.router_settings.values()) and all(self.sysctls.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "router_settings": self.router_settings,
            "sysctls": self.sysctls,
            "qdisc": self.qdisc,
            "notes": self.notes,
            "ok": self.ok,
        }


def router_profile(opt: OptimizationConfig) -> dict[str, Any]:
    """Translate the profile into the router settings we will push."""

    settings: dict[str, Any] = {}
    if opt.turbo:
        settings.update(
            {
                # WMM carries the 802.11e access categories RTP needs for priority.
                "wmm": True,
                # Power saving parks the radio and adds tens of ms of jitter.
                "power_saving": False,
                "wifi_power": "high",
                # UPnP lets SIP endpoints open their own media pinholes.
                "upnp": True,
                # Port filtering is a second firewall in front of ours.
                "port_filter": False,
                "jumbo_frames": True,
                "ethernet_failover": True,
                "ipv6_enabled": True,
            }
        )
        if opt.wan_mtu:
            settings["mtu"] = opt.wan_mtu
    if opt.prefer_5ghz:
        settings["wifi_bandwidth_5"] = "160"
        settings["wifi_mode_5"] = "ax"
    return settings


def sysctl_profile(opt: OptimizationConfig) -> dict[str, str]:
    """Host kernel tuning applied alongside the router settings."""

    if not opt.turbo:
        return {}
    return {
        "net.ipv4.tcp_congestion_control": opt.congestion_control,
        "net.core.default_qdisc": opt.qdisc,
        "net.core.rmem_max": "33554432",
        "net.core.wmem_max": "33554432",
        "net.core.netdev_max_backlog": "16384",
        "net.core.somaxconn": "4096",
        "net.ipv4.tcp_rmem": " ".join(str(v) for v in opt.tcp_rmem),
        "net.ipv4.tcp_wmem": " ".join(str(v) for v in opt.tcp_wmem),
        "net.ipv4.tcp_mtu_probing": "1",
        "net.ipv4.tcp_slow_start_after_idle": "0",
        "net.ipv4.tcp_notsent_lowat": "131072",
        "net.ipv4.tcp_fastopen": "3",
        "net.ipv4.tcp_window_scaling": "1",
        "net.ipv4.tcp_sack": "1",
        "net.ipv4.tcp_timestamps": "1",
        # Multipath TCP: lets a single TCP flow ride every uplink at once.
        "net.mptcp.enabled": "1",
        "net.mptcp.checksum_enabled": "0",
        # Multiple default routes with different source addresses are normal here.
        "net.ipv4.conf.all.rp_filter": "2",
        "net.ipv4.conf.default.rp_filter": "2",
        "net.ipv4.ip_forward": "1",
        "net.ipv6.conf.all.forwarding": "1",
        # A bonded gateway holds far more simultaneous flows than a single WAN.
        "net.netfilter.nf_conntrack_max": "1048576",
        "net.ipv4.ip_local_port_range": "10240 65535",
    }


def apply_sysctls(values: dict[str, str]) -> dict[str, bool]:
    """Write kernel parameters, tolerating ones this kernel does not have."""

    results: dict[str, bool] = {}
    for key, value in values.items():
        result = run(["sysctl", "-w", f"{key}={value}"], quiet=True, allow_missing=True)
        ok = result.ok or result.skipped
        if not ok:
            # Absent knobs (no MPTCP, no conntrack module) are not failures.
            stderr = result.stderr.lower()
            if "cannot stat" in stderr or "no such file" in stderr or "read-only" in stderr:
                log.debug("sysctl %s unavailable on this kernel; skipping", key)
                ok = True
        results[key] = ok
    return results


def persist_sysctls(values: dict[str, str], path: str = "/etc/sysctl.d/99-turbobond.conf") -> bool:
    """Make the tuning survive a reboot."""

    if is_dry_run():
        log.info("[dry-run] would persist %d sysctls to %s", len(values), path)
        return True
    body = ["# Managed by turbobond. Do not edit; regenerated on every activation.", ""]
    body += [f"{k} = {v}" for k, v in sorted(values.items())]
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(body) + "\n")
        return True
    except OSError as exc:
        log.warning("could not persist sysctls to %s: %s", path, exc)
        return False


def apply_qdisc(interfaces: list[str], qdisc: str = "fq") -> dict[str, bool]:
    """Install a low-latency queue discipline on each uplink.

    ``cake`` is preferred where available because it does flow isolation and
    bufferbloat control in one shot; ``fq`` is the fallback.
    """

    results: dict[str, bool] = {}
    if which("tc") is None and not is_dry_run():
        log.info("tc not installed; leaving queue disciplines at kernel defaults")
        return dict.fromkeys(interfaces, True)

    for iface in interfaces:
        applied = False
        for candidate in ("cake", qdisc, "fq_codel"):
            result = run(
                ["tc", "qdisc", "replace", "dev", iface, "root", candidate],
                quiet=True,
                allow_missing=True,
            )
            if result.ok or result.skipped:
                log.info("qdisc %s active on %s", candidate, iface)
                applied = True
                break
        results[iface] = applied
    return results


class RouterProvisioner:
    """Owns the full apply/re-search cycle for the tuning profile."""

    def __init__(self, admin: RouterAdmin, opt: OptimizationConfig) -> None:
        self.admin = admin
        self.opt = opt
        self._search_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self.last_report = ProvisionReport()

    async def apply(self, interfaces: list[str] | None = None) -> ProvisionReport:
        """Apply both halves of the profile once."""

        report = ProvisionReport()
        report.notes.append(f"profile={self.opt.profile} turbo={self.opt.turbo} search={self.opt.search}")

        settings = router_profile(self.opt)
        if settings:
            try:
                report.router_settings = await self.admin.apply_optimization(settings)
            except RouterError as exc:
                log.warning("router-side tuning incomplete: %s", exc)
                report.notes.append(f"router tuning skipped: {exc}")
                report.router_settings = dict.fromkeys(settings, False)

        sysctls = sysctl_profile(self.opt)
        if sysctls:
            report.sysctls = await asyncio.to_thread(apply_sysctls, sysctls)
            await asyncio.to_thread(persist_sysctls, sysctls)

        if interfaces:
            report.qdisc = await asyncio.to_thread(apply_qdisc, interfaces, self.opt.qdisc)

        failed = [k for k, v in report.router_settings.items() if not v]
        if failed:
            report.notes.append(
                "router firmware did not expose these settings: " + ", ".join(sorted(failed))
            )
        self.last_report = report
        return report

    async def search_once(self, interfaces: list[str] | None = None) -> dict[str, Any]:
        """One re-optimization sweep: re-read the radio and re-pin the best band."""

        findings: dict[str, Any] = {}
        status = await self.admin.status()
        findings["rssi"] = status.rssi
        findings["sinr"] = status.sinr
        findings["bands"] = status.bands
        findings["network_type"] = status.network_type

        if not self.opt.band_search:
            return findings

        # A weak or noisy carrier link is worth re-acquiring; a healthy one is not
        # worth the seconds of downtime a band re-lock costs.
        weak = (status.rsrp is not None and status.rsrp < -105) or (status.sinr is not None and status.sinr < 3)
        if weak:
            log.info("carrier signal is weak (rsrp=%s sinr=%s); requesting a network re-scan", status.rsrp, status.sinr)
            try:
                findings["rescan"] = await self.admin.set_values({"network_pref": "auto"})
            except RouterError as exc:
                findings["rescan_error"] = str(exc)
        if interfaces:
            findings["qdisc"] = await asyncio.to_thread(apply_qdisc, interfaces, self.opt.qdisc)
        return findings

    async def start_search_loop(self, interfaces: list[str] | None = None) -> None:
        """Run :meth:`search_once` on the configured interval until stopped."""

        if not self.opt.search or self._search_task is not None:
            return
        self._stop.clear()

        async def _loop() -> None:
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.opt.search_interval_s)
                    return
                except TimeoutError:
                    pass
                try:
                    await self.search_once(interfaces)
                except Exception as exc:  # keep the loop alive across transient errors
                    log.warning("optimization sweep failed: %s", exc)

        self._search_task = asyncio.create_task(_loop(), name="turbobond-search")
        log.info("continuous optimization search running every %.0fs", self.opt.search_interval_s)

    async def stop(self) -> None:
        self._stop.set()
        if self._search_task is not None:
            self._search_task.cancel()
            try:
                await self._search_task
            except (asyncio.CancelledError, Exception):
                pass
            self._search_task = None
