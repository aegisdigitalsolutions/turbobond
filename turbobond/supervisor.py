"""The activation state machine.

One call to :meth:`Supervisor.activate` brings the entire system up, in the only
order that works:

1. preflight and dependency installation
2. sign in to the router web administrator
3. discover the uplinks and start monitoring them
4. apply the tuning profile (router settings, kernel, queue disciplines)
5. program per-link policy routing and MPTCP
6. bring up the bonded datapath (tunnel when a concentrator exists, weighted
   ECMP when it does not)
7. start the shadowsocks client for the second route
8. install the SIP firewall and voice prioritisation
9. turn the host into the LAN gateway so attached devices are bonded too
10. start the route selector and the continuous optimization sweep

Every stage records its outcome, so a partial activation reports exactly which
stage degraded and why rather than failing opaquely. Stages that are not
essential to carrying traffic never abort the run.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from turbobond.bond import mptcp, routing
from turbobond.bond.tunnel import BondingTunnel, tunnel_supported
from turbobond.config import AppConfig, save_config
from turbobond.errors import ActivationError, TurboBondError
from turbobond.lan.devices import DeviceRegistry, read_neighbours
from turbobond.lan.gateway import LanGateway
from turbobond.links.discovery import discover_links, links_to_config
from turbobond.links.model import Link, LinkState
from turbobond.links.monitor import LinkMonitor
from turbobond.logging_setup import get_logger
from turbobond.preflight import run_preflight
from turbobond.router.netgear_m7pro import NighthawkAdmin, build_router_admin
from turbobond.router.provision import RouterProvisioner
from turbobond.sip.firewall import SipFirewall
from turbobond.sip.qos import apply_sip_qos
from turbobond.transport.selector import RouteSelector
from turbobond.transport.shadowsocks import ShadowsocksManager
from turbobond.util.cmd import set_dry_run

log = get_logger("supervisor")


class Phase(str, Enum):
    IDLE = "idle"
    PREFLIGHT = "preflight"
    ROUTER = "router"
    LINKS = "links"
    OPTIMIZATION = "optimization"
    ROUTING = "routing"
    BOND = "bond"
    TRANSPORT = "transport"
    SIP = "sip"
    LAN = "lan"
    SELECTOR = "selector"
    ACTIVE = "active"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPING = "stopping"


@dataclass
class StageResult:
    phase: Phase
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0
    # A degraded stage completed with reduced capability rather than failing.
    degraded: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "ok": self.ok,
            "degraded": self.degraded,
            "detail": self.detail,
            "duration_s": round(self.duration_s, 2),
            "data": self.data,
        }


ProgressCallback = Callable[[Phase, str, float], Awaitable[None] | None]


class Supervisor:
    """Owns every subsystem and the activation lifecycle."""

    def __init__(self, cfg: AppConfig, *, on_progress: ProgressCallback | None = None) -> None:
        self.cfg = cfg
        self.on_progress = on_progress
        self.phase = Phase.IDLE
        self.stages: list[StageResult] = []
        self.links: list[Link] = []

        self.router: NighthawkAdmin = build_router_admin(cfg.router)
        self.provisioner = RouterProvisioner(self.router, cfg.optimization)
        self.monitor: LinkMonitor | None = None
        self.tunnel: BondingTunnel | None = None
        self.shadowsocks = ShadowsocksManager(cfg.shadowsocks, run_dir=cfg.run_dir)
        self.firewall = SipFirewall(cfg.sip)
        self.gateway: LanGateway | None = None
        self.selector: RouteSelector | None = None
        self.devices = DeviceRegistry(default_route=cfg.routes.default_route)

        self._activating = asyncio.Lock()
        self._activated_ts = 0.0
        self._device_task: asyncio.Task[None] | None = None
        self._last_error = ""
        self._bond_mode = "none"

        if cfg.dry_run:
            set_dry_run(True)

    # ------------------------------------------------------------- progress

    async def _progress(self, phase: Phase, message: str, fraction: float) -> None:
        self.phase = phase
        log.info("[%s] %s", phase.value, message)
        if self.on_progress is None:
            return
        try:
            result = self.on_progress(phase, message, fraction)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            log.debug("progress callback raised: %s", exc)

    def _record(self, phase: Phase, ok: bool, detail: str, started: float, **data: Any) -> StageResult:
        degraded = bool(data.pop("degraded", False))
        stage = StageResult(
            phase=phase,
            ok=ok,
            detail=detail,
            data=data,
            duration_s=time.perf_counter() - started,
            degraded=degraded,
        )
        self.stages.append(stage)
        return stage

    # ------------------------------------------------------------ activation

    @property
    def active(self) -> bool:
        return self.phase in (Phase.ACTIVE, Phase.DEGRADED)

    async def activate(self, *, install_dependencies: bool = True) -> dict[str, Any]:
        """Bring the whole system up. Safe to call repeatedly."""

        if self._activating.locked():
            raise ActivationError("an activation is already running")

        async with self._activating:
            self.stages.clear()
            self._last_error = ""
            start = time.time()
            try:
                await self._stage_preflight(install_dependencies)
                await self._stage_router()
                await self._stage_links()
                await self._stage_optimization()
                await self._stage_routing()
                await self._stage_bond()
                await self._stage_transport()
                await self._stage_sip()
                await self._stage_lan()
                await self._stage_selector()
            except TurboBondError as exc:
                self.phase = Phase.FAILED
                self._last_error = exc.message
                log.error("activation failed during %s: %s", self.phase.value, exc.message)
                return self.status() | {"error": exc.as_dict()}
            except Exception as exc:
                self.phase = Phase.FAILED
                self._last_error = str(exc)
                log.exception("activation failed unexpectedly")
                return self.status() | {"error": {"code": "internal", "message": str(exc)}}

            degraded = [s for s in self.stages if s.degraded or not s.ok]
            self.phase = Phase.DEGRADED if degraded else Phase.ACTIVE
            self._activated_ts = time.time()
            await self._progress(
                self.phase,
                f"activation complete in {time.time() - start:.1f}s"
                + (f" with {len(degraded)} degraded stage(s)" if degraded else ""),
                1.0,
            )
            self._start_device_tracking()
            self._persist()
            return self.status()

    # ------------------------------------------------------------ the stages

    async def _stage_preflight(self, install: bool) -> None:
        started = time.perf_counter()
        await self._progress(Phase.PREFLIGHT, "checking dependencies", 0.05)
        report = await asyncio.to_thread(run_preflight, self.cfg, install=install)
        if not report.ok:
            detail = "; ".join(f"{c.name}: {c.detail}" for c in report.blocking)
            self._record(Phase.PREFLIGHT, False, detail, started, report=report.as_dict())
            raise ActivationError(
                f"cannot activate: {detail}",
                remedy=report.blocking[0].remedy if report.blocking[0].remedy else None,
            )
        self._record(
            Phase.PREFLIGHT,
            True,
            f"{len(report.degraded)} degraded check(s)",
            started,
            degraded=bool(report.degraded),
            report=report.as_dict(),
        )

    async def _stage_router(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.ROUTER, f"signing in to the router at {self.cfg.router.base_url}", 0.12)
        if not self.cfg.router.manage:
            self._record(Phase.ROUTER, True, "router management disabled", started)
            return

        status = await self.router.connect()
        if not status.reachable:
            # The bond does not depend on the router being reachable.
            self._record(
                Phase.ROUTER,
                False,
                status.error or "router unreachable",
                started,
                degraded=True,
                status=status.as_dict(),
            )
            return

        if self.cfg.sip.enabled and self.cfg.sip.disable_alg and status.authenticated:
            with contextlib.suppress(TurboBondError):
                await self.router.set_sip_alg(False)

        self._record(
            Phase.ROUTER,
            True,
            f"{status.model or 'router'} {status.firmware}".strip() or "connected",
            started,
            degraded=not status.authenticated,
            status=status.as_dict(),
        )

    async def _stage_links(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.LINKS, "discovering WAN uplinks", 0.22)
        self.links = await asyncio.to_thread(discover_links, self.cfg)
        if not self.links:
            self._record(Phase.LINKS, False, "no uplinks found", started)
            raise ActivationError(
                "no WAN uplink was found",
                remedy="Connect at least one internet-facing interface and re-run activation.",
            )

        self.monitor = LinkMonitor(
            self.links,
            targets=self.cfg.routes.probe_targets,
            interval_s=self.cfg.routes.probe_interval_s,
            on_state_change=self._on_link_state_change,
        )
        await self.monitor.start()

        usable = self.monitor.usable_links()
        if not usable:
            self._record(Phase.LINKS, False, "every uplink failed its health probe", started)
            raise ActivationError(
                "no uplink passed its health check",
                remedy="Check that at least one WAN connection can reach the internet.",
            )

        # Persist what we discovered so the next start is deterministic.
        self.cfg.links = links_to_config(self.links)
        self._record(
            Phase.LINKS,
            True,
            f"{len(usable)}/{len(self.links)} uplink(s) healthy",
            started,
            degraded=len(usable) < 2,
            links=[link.as_dict() for link in self.links],
        )

    async def _stage_optimization(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.OPTIMIZATION, f"applying the {self.cfg.optimization.profile} profile", 0.35)
        interfaces = [link.interface for link in self.links if link.usable]
        report = await self.provisioner.apply(interfaces)
        self._record(
            Phase.OPTIMIZATION,
            True,
            f"profile {self.cfg.optimization.profile} applied",
            started,
            degraded=not report.ok,
            report=report.as_dict(),
        )

    async def _stage_routing(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.ROUTING, "programming policy routing and MPTCP", 0.45)
        tables = await asyncio.to_thread(routing.program_link_tables, self.links)
        mptcp_state = await asyncio.to_thread(mptcp.configure_endpoints, self.links)
        self._record(
            Phase.ROUTING,
            tables.ok,
            f"{len(tables.tables)} link table(s) programmed",
            started,
            degraded=not tables.ok or not mptcp_state.available,
            routing=tables.as_dict(),
            mptcp=mptcp_state.as_dict(),
        )

    async def _stage_bond(self) -> None:
        started = time.perf_counter()
        usable = [link for link in self.links if link.usable]

        if self.cfg.concentrator.enabled and self.cfg.concentrator.host:
            supported, reason = tunnel_supported()
            if supported:
                await self._progress(Phase.BOND, "bringing up the bonded tunnel", 0.55)
                self.tunnel = BondingTunnel(self.cfg.concentrator, self.links, sip=self.cfg.sip)
                try:
                    await self.tunnel.start()
                except TurboBondError as exc:
                    log.warning("bonded tunnel could not start (%s); falling back to local aggregation", exc.message)
                    self.tunnel = None
                else:
                    report = await asyncio.to_thread(
                        routing.install_tunnel_default,
                        self.cfg.concentrator.tun_device,
                        self.cfg.concentrator.tunnel_ip_remote,
                        self.cfg.concentrator.host,
                        self.links,
                    )
                    await asyncio.to_thread(routing.add_bypass_routes, self.cfg.routes.direct_cidrs, self.links)
                    self._bond_mode = "tunnel"
                    self._record(
                        Phase.BOND,
                        report.ok,
                        f"packet-level bonding across {len(usable)} uplink(s)",
                        started,
                        degraded=not report.ok,
                        mode="tunnel",
                        routing=report.as_dict(),
                        tunnel=self.tunnel.snapshot(),
                    )
                    return
            else:
                log.warning("packet-level bonding unavailable: %s", reason)

        await self._progress(Phase.BOND, "bringing up weighted multipath aggregation", 0.55)
        report = await asyncio.to_thread(routing.install_ecmp_default, self.links)
        self._bond_mode = "ecmp"
        self._record(
            Phase.BOND,
            report.ok,
            f"weighted multipath across {len(usable)} uplink(s): {report.default_route}",
            started,
            # Local mode aggregates across flows but not within one connection.
            degraded=True,
            mode="ecmp",
            routing=report.as_dict(),
            note=(
                "No concentrator is configured, so a single connection stays on one uplink. "
                "Deploy turbobond-server and set concentrator.host for per-packet aggregation."
            ),
        )

    async def _stage_transport(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.TRANSPORT, "starting the shadow route", 0.68)
        if not self.cfg.shadowsocks.enabled:
            self._record(Phase.TRANSPORT, True, "shadow route disabled", started)
            return
        if not self.cfg.shadowsocks.usable:
            self._record(
                Phase.TRANSPORT,
                True,
                "shadow route has no server configured; only the direct route is available",
                started,
                degraded=True,
            )
            return
        try:
            await self.shadowsocks.start()
        except TurboBondError as exc:
            self._record(Phase.TRANSPORT, False, exc.message, started, degraded=True)
            return
        self._record(
            Phase.TRANSPORT,
            True,
            f"shadow route ready via {self.cfg.shadowsocks.host}:{self.cfg.shadowsocks.port}",
            started,
            shadowsocks=self.shadowsocks.snapshot(),
        )

    async def _stage_sip(self) -> None:
        started = time.perf_counter()
        mode = "wide open" if self.cfg.sip.wide_open else "stateful"
        await self._progress(Phase.SIP, f"installing {mode} SIP firewall rules", 0.78)

        # Pin signalling to one uplink so the far end never sees a source flap.
        pin_link = self._resolve_sip_link()
        if pin_link is not None:
            await asyncio.to_thread(routing.pin_traffic_to_link, pin_link, mark=routing.MARK_SIP)

        self.firewall.lan_interface = self.cfg.lan.interface
        self.firewall.tun_interface = self.cfg.concentrator.tun_device if self.tunnel else ""
        report = await asyncio.to_thread(self.firewall.apply)

        interfaces = [link.interface for link in self.links if link.usable]
        qos = await asyncio.to_thread(apply_sip_qos, interfaces, self.cfg.sip)

        self._record(
            Phase.SIP,
            report.applied,
            f"SIP {mode}: ports {report.signalling_ports}, RTP {report.rtp_range}",
            started,
            degraded=not report.ok,
            firewall=report.as_dict(),
            qos=qos.as_dict(),
            pinned_to=pin_link.name if pin_link else "",
        )

    def _resolve_sip_link(self) -> Link | None:
        if not self.cfg.sip.pin_to_link:
            # Default to the lowest-latency unmetered uplink.
            candidates = [link for link in self.links if link.usable and not link.metered]
            candidates = candidates or [link for link in self.links if link.usable]
            if not candidates:
                return None
            return min(candidates, key=lambda link: max(link.health.rtt_ms, 0.01))
        for link in self.links:
            if link.name == self.cfg.sip.pin_to_link and link.usable:
                return link
        log.warning("sip.pin_to_link names %r, which is not a usable uplink", self.cfg.sip.pin_to_link)
        return None

    async def _stage_lan(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.LAN, "putting every attached device on the bond", 0.88)
        if not self.cfg.lan.enabled:
            self._record(Phase.LAN, True, "LAN gateway mode disabled", started)
            return

        self.gateway = LanGateway(
            self.cfg.lan,
            self.cfg.routes,
            self.cfg.shadowsocks,
            self.cfg.sip,
            egress_interfaces=[link.interface for link in self.links if link.usable],
            tunnel_interface=self.cfg.concentrator.tun_device if self.tunnel else "",
        )
        report = await asyncio.to_thread(self.gateway.apply, active_route=self.cfg.routes.default_route)
        await self._refresh_devices()
        self.devices.mark_bonded(True)
        self._record(
            Phase.LAN,
            report.ok,
            f"gateway on {report.lan_interface or 'auto'}, {len(self.devices.online())} device(s) bonded",
            started,
            degraded=not report.ok,
            gateway=report.as_dict(),
            devices=self.devices.snapshot(),
        )

    async def _stage_selector(self) -> None:
        started = time.perf_counter()
        await self._progress(Phase.SELECTOR, "starting route selection and continuous optimization", 0.95)
        self.selector = RouteSelector(
            self.cfg.routes,
            on_switch=self._on_route_switch,
            availability=self._route_available,
        )
        await self.selector.start()

        interfaces = [link.interface for link in self.links if link.usable]
        await self.provisioner.start_search_loop(interfaces)

        self._record(
            Phase.SELECTOR,
            True,
            f"active route: {self.selector.state.active}",
            started,
            selector=self.selector.snapshot(),
        )

    # ------------------------------------------------------------- callbacks

    async def _route_available(self, name: str) -> tuple[bool, str]:
        """Whether a route's machinery is up, used by the selector."""

        if name == "direct":
            usable = [link for link in self.links if link.usable]
            if not usable:
                return False, "no usable uplink"
            return True, ""
        if not self.cfg.shadowsocks.enabled:
            return False, "the shadow route is turned off"
        if not self.cfg.shadowsocks.usable:
            return False, "no shadowsocks server is configured"
        if not await self.shadowsocks.healthy():
            return False, "the shadowsocks client is not accepting connections"
        return True, ""

    async def _on_route_switch(self, old: str, new: str) -> None:
        """Re-point LAN traffic when the active route changes."""

        if self.gateway is not None:
            await asyncio.to_thread(self.gateway.switch_route, new)
        self.devices.default_route = new
        log.info("LAN traffic now egresses through the %s route", new)

    def _on_link_state_change(self, link: Link, old: LinkState, new: LinkState) -> None:
        """Re-weight the bond whenever a link changes state."""

        if self.tunnel is not None:
            self.tunnel.refresh_links(self.links)
        if self._bond_mode == "ecmp":
            # Rebuild the multipath route so a dead link stops receiving flows.
            routing.install_ecmp_default(self.links)
        if new is LinkState.DOWN and self.cfg.sip.pin_to_link == link.name:
            replacement = self._resolve_sip_link()
            if replacement is not None:
                routing.pin_traffic_to_link(replacement, mark=routing.MARK_SIP)
                log.info("SIP re-pinned from %s to %s", link.name, replacement.name)

    # --------------------------------------------------------------- devices

    async def _refresh_devices(self) -> None:
        neighbours = await asyncio.to_thread(read_neighbours)
        self.devices.merge(neighbours, source="neighbour-table")
        if self.cfg.router.manage:
            with contextlib.suppress(TurboBondError):
                self.devices.merge(await self.router.devices(), source="router")
        self.devices.mark_bonded(self.active or self.phase is Phase.LAN)

    def _start_device_tracking(self) -> None:
        if self._device_task is not None:
            return

        async def _loop() -> None:
            while True:
                await asyncio.sleep(30)
                with contextlib.suppress(Exception):
                    await self._refresh_devices()

        self._device_task = asyncio.create_task(_loop(), name="turbobond-devices")

    # -------------------------------------------------------------- teardown

    async def deactivate(self) -> dict[str, Any]:
        """Tear everything down and put the host back the way it was."""

        self.phase = Phase.STOPPING
        log.info("deactivating")

        if self._device_task is not None:
            self._device_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._device_task
            self._device_task = None

        for name, coro in (
            ("selector", self.selector.stop() if self.selector else None),
            ("provisioner", self.provisioner.stop()),
            ("monitor", self.monitor.stop() if self.monitor else None),
            ("tunnel", self.tunnel.stop() if self.tunnel else None),
            ("shadowsocks", self.shadowsocks.stop()),
            ("router", self.router.close()),
        ):
            if coro is None:
                continue
            try:
                await coro
            except Exception as exc:
                log.warning("error stopping %s: %s", name, exc)

        if self.gateway is not None:
            await asyncio.to_thread(self.gateway.teardown)
        await asyncio.to_thread(self.firewall.teardown)
        await asyncio.to_thread(routing.teardown, self.links)
        await asyncio.to_thread(mptcp.flush)

        self.tunnel = None
        self.selector = None
        self.monitor = None
        self.gateway = None
        self.phase = Phase.IDLE
        self._activated_ts = 0.0
        log.info("deactivated")
        return self.status()

    def _persist(self) -> None:
        try:
            save_config(self.cfg)
        except Exception as exc:
            log.warning("could not persist the configuration: %s", exc)

    # ---------------------------------------------------------------- status

    def status(self) -> dict[str, Any]:
        """Everything the dashboard renders."""

        usable = [link for link in self.links if link.usable]
        aggregate_up = round(sum(link.uplink_mbps for link in usable), 2)
        aggregate_down = round(sum(link.downlink_mbps for link in usable), 2)

        return {
            "phase": self.phase.value,
            "active": self.active,
            "bond_mode": self._bond_mode,
            "uptime_s": round(time.time() - self._activated_ts, 1) if self._activated_ts else 0,
            "last_error": self._last_error,
            "dry_run": self.cfg.dry_run,
            "profile": self.cfg.optimization.profile,
            "aggregate": {
                "uplinks": len(usable),
                "up_mbps": aggregate_up,
                "down_mbps": aggregate_down,
            },
            "stages": [stage.as_dict() for stage in self.stages],
            "links": self.monitor.snapshot() if self.monitor else {"links": [link.as_dict() for link in self.links]},
            "tunnel": self.tunnel.snapshot() if self.tunnel else {"running": False, "mode": self._bond_mode},
            "shadowsocks": self.shadowsocks.snapshot(),
            "routes": self.selector.snapshot() if self.selector else {"active": self.cfg.routes.default_route},
            "sip": self.firewall.last_report.as_dict(),
            "lan": self.gateway.snapshot() if self.gateway else {"enabled": self.cfg.lan.enabled},
            "devices": self.devices.snapshot(),
            "optimization": self.provisioner.last_report.as_dict(),
        }

    async def router_status(self) -> dict[str, Any]:
        status = await self.router.status()
        return status.as_dict()
