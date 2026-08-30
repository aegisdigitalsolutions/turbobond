"""HTTP API and the single-page control panel.

The user-facing contract is deliberately small: ``POST /api/signin`` and
everything else happens on its own. The remaining endpoints exist so the
dashboard can show what the app did and so an operator can override a decision.
"""

from __future__ import annotations

import asyncio
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Annotated, Any

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from turbobond.app.activation import ActivationController
from turbobond.app.auth import CSRF_HEADER, SESSION_COOKIE, AuthManager, Session
from turbobond.bond import provision
from turbobond.config import AppConfig, load_config, save_config
from turbobond.errors import AuthError, TurboBondError
from turbobond.logging_setup import configure as configure_logging
from turbobond.logging_setup import get_logger, ring_buffer
from turbobond.supervisor import Supervisor
from turbobond.transport.profiles import describe_routes
from turbobond.util.cmd import audit_log
from turbobond.version import __version__

log = get_logger("app.api")

WEB_DIR = Path(__file__).parent / "web"


# --------------------------------------------------------------------- models


class SignInRequest(BaseModel):
    username: str = "admin"
    password: str
    # Everything below is optional; supplying it on the sign-in screen is what
    # lets a first-time user finish setup without editing a config file.
    router_password: str | None = None
    router_host: str | None = None
    concentrator_host: str | None = None
    concentrator_port: int | None = None
    concentrator_psk: str | None = None
    shadowsocks_host: str | None = None
    shadowsocks_port: int | None = None
    shadowsocks_password: str | None = None
    shadowsocks_method: str | None = None
    activate: bool = True


class RouteRequest(BaseModel):
    route: str = Field(pattern="^(direct|shadow)$")


class DeviceRouteRequest(BaseModel):
    device: str
    route: str = Field(pattern="^(direct|shadow)$")


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class ConfigPatch(BaseModel):
    """Partial config update. Only the fields present are applied."""

    values: dict[str, Any]


# ------------------------------------------------------------------ app state


class AppState:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self.auth = AuthManager(cfg)
        self.supervisor = Supervisor(cfg)
        self.activation = ActivationController(self.supervisor)
        self.started_ts = time.time()


def app_state(request: Request) -> AppState:
    return request.app.state.tb  # type: ignore[no-any-return]


def current_session(
    request: Request,
    turbobond_session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> Session:
    session = app_state(request).auth.resolve(turbobond_session)
    if session is None:
        raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "sign in first"})
    return session


def csrf_guard(
    request: Request,
    session: Annotated[Session, Depends(current_session)],
    csrf: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
) -> Session:
    try:
        app_state(request).auth.check_csrf(session, csrf)
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=exc.as_dict()) from exc
    return session


# These aliases must live at module scope: with postponed annotations FastAPI
# resolves endpoint type hints against this module's globals, so a dependency
# alias defined inside the factory would be invisible and silently degrade into
# a query parameter.
SessionDep = Annotated[Session, Depends(current_session)]
GuardedDep = Annotated[Session, Depends(csrf_guard)]


def create_app(cfg: AppConfig | None = None) -> FastAPI:
    """Build the FastAPI application."""

    cfg = cfg or load_config()
    configure_logging(cfg.log_level)
    state = AppState(cfg)

    app = FastAPI(
        title="turbobond",
        version=__version__,
        description="Multi-WAN bandwidth bonding gateway",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.tb = state

    # ---------------------------------------------------------------- handlers

    @app.exception_handler(TurboBondError)
    async def _turbobond_error(_: Request, exc: TurboBondError) -> JSONResponse:
        status = 401 if isinstance(exc, AuthError) else 400
        return JSONResponse(status_code=status, content={"detail": exc.as_dict()})

    # ------------------------------------------------------------------- pages

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        html = WEB_DIR / "index.html"
        if not html.exists():
            return HTMLResponse("<h1>turbobond</h1><p>UI assets are missing.</p>", status_code=500)
        return HTMLResponse(html.read_text())

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    # -------------------------------------------------------------------- auth

    @app.get("/api/bootstrap")
    async def bootstrap() -> dict[str, Any]:
        """What the sign-in screen needs before anyone has signed in."""

        return {
            "version": __version__,
            "enrolled": state.auth.enrolled,
            "auto_activate": cfg.auto_activate_on_login,
            "dry_run": cfg.dry_run,
            "router_host": cfg.router.host,
            "profile": cfg.optimization.profile,
            "routes": describe_routes(),
            "needs_router_password": cfg.router.manage and not cfg.router.password,
            "needs_shadowsocks": cfg.shadowsocks.enabled and not cfg.shadowsocks.usable,
            "needs_concentrator": not (cfg.concentrator.enabled and cfg.concentrator.host),
        }

    @app.post("/api/signin")
    async def signin(payload: SignInRequest, request: Request, response: Response) -> dict[str, Any]:
        remote = request.client.host if request.client else ""
        try:
            session = state.auth.sign_in(payload.username, payload.password, remote=remote)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=exc.as_dict()) from exc

        _apply_signin_settings(cfg, payload)

        response.set_cookie(
            SESSION_COOKIE,
            state.auth.issue_cookie(session),
            httponly=True,
            samesite="strict",
            max_age=cfg.auth.session_ttl_s,
            path="/",
        )

        activation: dict[str, Any] | None = None
        if payload.activate and cfg.auto_activate_on_login:
            activation = (await state.activation.start()).as_dict()

        return {
            "username": session.username,
            "csrf": session.csrf,
            "activation": activation,
            "auto_activate": cfg.auto_activate_on_login,
        }

    @app.post("/api/signout")
    async def signout(session: SessionDep, response: Response) -> dict[str, str]:
        state.auth.sign_out(session)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"status": "signed out"}

    @app.post("/api/password")
    async def change_password(payload: PasswordChangeRequest, session: GuardedDep) -> dict[str, str]:
        try:
            state.auth.change_password(session, payload.current_password, payload.new_password)
        except AuthError as exc:
            raise HTTPException(status_code=400, detail=exc.as_dict()) from exc
        return {"status": "password changed"}

    @app.get("/api/session")
    async def session_info(session: SessionDep) -> dict[str, Any]:
        return {"session": session.as_dict(), "csrf": session.csrf}

    # ------------------------------------------------------------- activation

    @app.post("/api/activate")
    async def activate(session: GuardedDep) -> dict[str, Any]:
        return (await state.activation.start()).as_dict()

    @app.post("/api/deactivate")
    async def deactivate(session: GuardedDep) -> dict[str, Any]:
        return await state.activation.stop()

    @app.get("/api/activation")
    async def activation_state(session: SessionDep, since: int = 0) -> dict[str, Any]:
        data = state.activation.state.as_dict()
        data["new_events"] = state.activation.events_since(since)
        return data

    @app.get("/api/activation/stream")
    async def activation_stream(session: SessionDep) -> StreamingResponse:
        """Server-sent events so the browser sees progress as it happens."""

        async def _events():
            seq = 0
            deadline = time.time() + 900
            while time.time() < deadline:
                for event in state.activation.events_since(seq):
                    seq = max(seq, event["seq"])
                    yield f"data: {json.dumps(event)}\n\n"
                if not state.activation.state.running and seq > 0:
                    yield f"data: {json.dumps({'phase': state.supervisor.phase.value, 'done': True})}\n\n"
                    return
                await asyncio.sleep(0.4)

        return StreamingResponse(
            _events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ----------------------------------------------------------------- status

    @app.get("/api/status")
    async def status(session: SessionDep) -> dict[str, Any]:
        return state.supervisor.status() | {
            "version": __version__,
            "app_uptime_s": round(time.time() - state.started_ts, 1),
            "activation": state.activation.state.as_dict(),
        }

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        """Unauthenticated liveness probe."""

        return {"status": "ok", "version": __version__, "phase": state.supervisor.phase.value}

    @app.get("/api/router")
    async def router_status(session: SessionDep) -> dict[str, Any]:
        return await state.supervisor.router_status()

    @app.get("/api/links")
    async def links(session: SessionDep) -> dict[str, Any]:
        monitor = state.supervisor.monitor
        if monitor is None:
            return {"links": [link.as_dict() for link in state.supervisor.links]}
        return monitor.snapshot()

    @app.get("/api/routes")
    async def routes(session: SessionDep) -> dict[str, Any]:
        selector = state.supervisor.selector
        return {
            "available": describe_routes(),
            "selector": selector.snapshot() if selector else {"active": cfg.routes.default_route},
        }

    @app.post("/api/routes/select")
    async def select_route(payload: RouteRequest, session: GuardedDep) -> dict[str, Any]:
        selector = state.supervisor.selector
        if selector is None:
            raise HTTPException(status_code=409, detail={"code": "not_active", "message": "activate the bond first"})
        ok = await selector.set_preferred(payload.route)
        if not ok:
            raise HTTPException(
                status_code=409,
                detail={"code": "route_unavailable", "message": f"the {payload.route} route is not usable right now"},
            )
        save_config(cfg)
        return selector.snapshot()

    @app.get("/api/devices")
    async def devices(session: SessionDep) -> dict[str, Any]:
        return state.supervisor.devices.snapshot()

    @app.post("/api/devices/route")
    async def set_device_route(payload: DeviceRouteRequest, session: GuardedDep) -> dict[str, Any]:
        gateway = state.supervisor.gateway
        state.supervisor.devices.set_route(payload.device, payload.route)
        cfg.lan.device_routes[payload.device] = payload.route  # type: ignore[assignment]
        if gateway is not None:
            gateway.set_device_route(payload.device, payload.route)
        save_config(cfg)
        return state.supervisor.devices.snapshot()

    @app.get("/api/sip")
    async def sip_status(session: SessionDep) -> dict[str, Any]:
        return {
            "config": cfg.sip.model_dump(mode="json"),
            "report": state.supervisor.firewall.last_report.as_dict(),
            "verify": state.supervisor.firewall.verify(),
            "ruleset": state.supervisor.firewall.build_nft_ruleset(),
        }

    @app.get("/api/logs")
    async def logs(session: SessionDep, after: int = 0, limit: int = 300) -> dict[str, Any]:
        return {"records": ring_buffer.tail(after_seq=after, limit=limit)}

    @app.get("/api/commands")
    async def commands(session: SessionDep, limit: int = 200) -> dict[str, Any]:
        """Every privileged command turbobond issued, so nothing is a black box."""

        return {"commands": audit_log(limit=limit)}

    # ----------------------------------------------------------------- config

    @app.get("/api/config")
    async def get_config(session: SessionDep) -> dict[str, Any]:
        return cfg.redacted()

    @app.patch("/api/config")
    async def patch_config(payload: ConfigPatch, session: GuardedDep) -> dict[str, Any]:
        """Apply a partial config update and persist it."""

        try:
            merged = cfg.model_dump()
            _deep_merge(merged, payload.values)
            updated = AppConfig.model_validate(merged)
        except Exception as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_config", "message": str(exc)}) from exc

        cfg.absorb(updated)
        cfg.assign_table_ids()
        save_config(cfg)
        return cfg.redacted()

    # --------------------------------------------------------------- download

    @app.get("/api/download/concentrator")
    async def download_concentrator(session: SessionDep) -> StreamingResponse:
        """Ship the concentrator half, pre-seeded with this install's key.

        Packet-level bonding needs a peer. This produces a tarball the operator
        drops on a VPS and runs, with the matching PSK already filled in, so the
        two halves never have to be paired by hand.
        """

        cfg.concentrator.ensure_psk()
        save_config(cfg)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, content in _concentrator_bundle(cfg).items():
                data = content.encode()
                info = tarfile.TarInfo(name=f"turbobond-concentrator/{name}")
                info.size = len(data)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(data))
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type="application/gzip",
            headers={"Content-Disposition": 'attachment; filename="turbobond-concentrator.tar.gz"'},
        )

    @app.get("/api/download/config")
    async def download_config(session: SessionDep) -> Response:
        """The running configuration, with secrets redacted."""

        import yaml

        body = yaml.safe_dump(cfg.redacted(), sort_keys=False)
        return Response(
            body,
            media_type="application/x-yaml",
            headers={"Content-Disposition": 'attachment; filename="turbobond.yaml"'},
        )

    @app.get("/api/download/diagnostics")
    async def download_diagnostics(session: SessionDep) -> Response:
        """Everything needed to debug an install, in one JSON file."""

        payload = {
            "generated_ts": time.time(),
            "version": __version__,
            "status": state.supervisor.status(),
            "config": cfg.redacted(),
            "logs": ring_buffer.tail(limit=1000),
            "commands": audit_log(limit=500),
            "sip_ruleset": state.supervisor.firewall.build_nft_ruleset(),
            "sip_verify": state.supervisor.firewall.verify(),
        }
        return Response(
            json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="turbobond-diagnostics.json"'},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        icon = WEB_DIR / "favicon.svg"
        if icon.exists():
            return FileResponse(icon, media_type="image/svg+xml")
        return Response(status_code=204)

    # -------------------------------------------------------------- lifecycle

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        if state.supervisor.active:
            log.info("shutting down; leaving the bond in place")

    return app


# ------------------------------------------------------------------- helpers


def _apply_signin_settings(cfg: AppConfig, payload: SignInRequest) -> None:
    """Fold optional first-run settings from the sign-in form into the config."""

    changed = False
    if payload.router_password:
        cfg.router.password = payload.router_password
        changed = True
    if payload.router_host:
        cfg.router.host = payload.router_host
        changed = True
    if payload.concentrator_host:
        cfg.concentrator.host = payload.concentrator_host
        cfg.concentrator.enabled = True
        changed = True
    if payload.concentrator_port:
        cfg.concentrator.port = payload.concentrator_port
        changed = True
    if payload.concentrator_psk:
        cfg.concentrator.psk_hex = payload.concentrator_psk
        changed = True
    if payload.shadowsocks_host:
        cfg.shadowsocks.host = payload.shadowsocks_host
        cfg.shadowsocks.enabled = True
        changed = True
    if payload.shadowsocks_port:
        cfg.shadowsocks.port = payload.shadowsocks_port
        changed = True
    if payload.shadowsocks_password:
        cfg.shadowsocks.password = payload.shadowsocks_password
        changed = True
    if payload.shadowsocks_method:
        cfg.shadowsocks.method = payload.shadowsocks_method
        changed = True
    if changed:
        try:
            save_config(cfg)
        except Exception as exc:
            log.warning("could not persist sign-in settings: %s", exc)


def _deep_merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


#: Re-exported so the bundle and the standalone installer pin the same set.
CONCENTRATOR_REQUIREMENTS = provision.CONCENTRATOR_REQUIREMENTS


def _package_sources() -> dict[str, str]:
    """The turbobond package itself, for a bundle that installs without a network index."""

    root = Path(__file__).resolve().parent.parent
    sources: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        try:
            sources[f"src/turbobond/{path.relative_to(root).as_posix()}"] = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
    return sources


def _concentrator_bundle(cfg: AppConfig) -> dict[str, str]:
    """Files that make up the downloadable concentrator package.

    The turbobond source travels inside the bundle. Pulling it from an index
    instead would mean the concentrator could only be installed from a machine
    that can reach a published copy of this exact version, which is not a
    dependency worth having on the far end of your own bond.
    """

    psk = cfg.concentrator.psk_hex
    port = cfg.concentrator.port
    peer_ip = cfg.concentrator.tunnel_ip_local.split("/")[0]
    server_ip = cfg.concentrator.tunnel_ip_remote
    settings = provision.ConcentratorSettings(
        psk=psk,
        port=port,
        server_ip=server_ip,
        peer_ip=peer_ip,
        mtu=cfg.concentrator.tunnel_mtu,
        reorder_ms=cfg.concentrator.reorder_timeout_ms,
    )

    install_sh = f"""#!/bin/sh
# turbobond concentrator installer.
# Run as root on a VPS with a single fast uplink and a public IP.
set -eu

echo "Installing the turbobond concentrator..."

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \\
        python3 python3-venv python3-pip iproute2 iptables ca-certificates
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip iproute2 iptables ca-certificates
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 py3-pip iproute2 iptables ca-certificates
fi

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {{
    echo "error: the concentrator needs Python 3.11 or newer." >&2
    exit 1
}}

# The source travels in this bundle, so there is nothing to fetch by name.
# Ubuntu 24.04 and Debian 12 refuse system-wide pip installs (PEP 668), hence
# the virtualenv. Creating one is the only real test that it can be done:
# 'python3 -m venv --help' succeeds even on images where ensurepip is missing.
VENV=/usr/local/lib/turbobond-concentrator
rm -rf "$VENV"
if python3 -m venv "$VENV" 2>/dev/null && [ -x "$VENV/bin/pip" ]; then
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet "$HERE/src"
    ln -sf "$VENV/bin/turbobond-server" /usr/local/bin/turbobond-server
else
    echo "no usable virtualenv; installing system-wide instead"
    rm -rf "$VENV"
    python3 -m pip install --break-system-packages "$HERE/src" \\
        || python3 -m pip install "$HERE/src"
fi

command -v turbobond-server >/dev/null 2>&1 || {{
    echo "error: turbobond-server was not installed; see the output above." >&2
    exit 1
}}

modprobe tun || true

# Kernel tuning. The concentrator terminates every uplink at once and NATs the
# client's whole LAN, so the defaults are sized well below what it has to
# absorb. Written as a drop-in so it survives reboots.
cat > {provision.SYSCTL_PATH} <<'SYSCTL'
{provision.SYSCTL_DROP_IN}SYSCTL

modprobe nf_conntrack 2>/dev/null || true
sysctl --system >/dev/null || true

install -m 0644 turbobond-concentrator.service /etc/systemd/system/turbobond-concentrator.service
systemctl daemon-reload
systemctl enable --now turbobond-concentrator
sleep 2
systemctl --no-pager --lines=0 status turbobond-concentrator || true

echo
echo "Concentrator running on UDP {port}."
echo "Open that port in your provider's firewall, then activate the client."
echo "Logs: journalctl -u turbobond-concentrator -f"
"""

    service = settings.unit_text()

    readme = f"""# turbobond concentrator

This is the far end of the bond. Without it, packets from a single connection
cannot be spread across several uplinks, because nothing would put them back
together.

## Install

Copy this directory to a VPS with a public IP and run:

    sudo sh install.sh

## What it does

- listens on UDP {port} for bonded sessions
- resequences packets that arrived across all of the client's uplinks
- NATs them out to the internet
- spreads return traffic back across the same uplinks, which is what makes
  download aggregation work
- tunes the kernel for the job: BBR, deep buffers and backlog, a conntrack
  table sized for a whole LAN, and no slow start after idle

The tuning is written to `/etc/sysctl.d/99-turbobond-concentrator.conf`, so it
survives reboots and applies before the service starts.

## Checking on it

    systemctl status turbobond-concentrator
    journalctl -u turbobond-concentrator -f

## Firewall

Allow inbound UDP {port} from the client's uplink addresses. The tunnel is
authenticated with ChaCha20-Poly1305, so unauthenticated datagrams are dropped
before they reach the datapath, but limiting the source range is still worth
doing.

## Pairing

The pre-shared key in `turbobond-concentrator.service` already matches this
install. Keep it secret; anyone holding it can open a bonded session.
"""

    requirements = ",\n    ".join(f'"{req}"' for req in CONCENTRATOR_REQUIREMENTS)
    src_pyproject = f"""[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "turbobond"
version = "{__version__}"
description = "turbobond bonding concentrator (server half)"
requires-python = ">=3.11"

# Only what the server half imports. The gateway's web stack is not needed
# here, so the concentrator host stays lean.
dependencies = [
    {requirements},
]

[project.scripts]
turbobond-server = "turbobond.bond.server:main"

[tool.setuptools.packages.find]
include = ["turbobond*"]

[tool.setuptools.package-data]
"turbobond.app" = ["web/*"]
"""

    return {
        "install.sh": install_sh,
        "turbobond-concentrator.service": service,
        "README.md": readme,
        "src/pyproject.toml": src_pyproject,
        **_package_sources(),
    }
