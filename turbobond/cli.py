"""Command line entry point.

``turbobond serve`` is what the systemd unit runs; everything else exists for
operators who want to inspect or drive the system without a browser.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import Any

from turbobond.config import AppConfig, load_config, save_config
from turbobond.errors import TurboBondError
from turbobond.logging_setup import configure as configure_logging
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import set_dry_run
from turbobond.version import __version__

log = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="turbobond",
        description="Multi-WAN bandwidth bonding gateway with SIP-transparent firewalling.",
    )
    parser.add_argument("--config", type=Path, default=None, help="path to turbobond.yaml")
    parser.add_argument("--log-level", default="", help="DEBUG, INFO, WARNING, ERROR")
    parser.add_argument("--dry-run", action="store_true", help="log every privileged action instead of running it")
    parser.add_argument("--version", action="version", version=f"turbobond {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the web app (this is the normal way to run turbobond)")
    serve.add_argument("--host", default="", help="bind address (default from config)")
    serve.add_argument("--port", type=int, default=0, help="bind port (default from config)")
    serve.add_argument("--no-activate", action="store_true", help="do not activate automatically on sign-in")

    up = sub.add_parser("up", help="activate the bond without starting the web app")
    up.add_argument("--no-install", action="store_true", help="do not install missing dependencies")

    sub.add_parser("down", help="tear the bond down and restore the previous configuration")
    sub.add_parser("status", help="print the current status as JSON")

    preflight = sub.add_parser("preflight", help="check dependencies and capabilities")
    preflight.add_argument("--install", action="store_true", help="install anything that is missing")

    sub.add_parser("links", help="list the discovered WAN uplinks")
    sub.add_parser("routes", help="show the two available routes")

    sip = sub.add_parser("sip", help="inspect or apply the SIP firewall policy")
    sip.add_argument("--apply", action="store_true", help="install the rules now")
    sip.add_argument("--show", action="store_true", help="print the generated ruleset")

    config_cmd = sub.add_parser("config", help="show or initialise the configuration")
    config_cmd.add_argument("--init", action="store_true", help="write a config file with defaults")

    sub.add_parser("gen-psk", help="print a fresh concentrator pre-shared key")

    return parser


def _load(args: argparse.Namespace) -> AppConfig:
    cfg = load_config(args.config)
    if args.log_level:
        cfg.log_level = args.log_level
    if args.dry_run:
        cfg.dry_run = True
    configure_logging(cfg.log_level)
    if cfg.dry_run:
        set_dry_run(True)
    return cfg


def _dump(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str))


# ------------------------------------------------------------------ commands


def cmd_serve(args: argparse.Namespace, cfg: AppConfig) -> int:
    import uvicorn

    from turbobond.app.api import create_app

    if args.no_activate:
        cfg.auto_activate_on_login = False

    host = args.host or cfg.auth.bind_host
    port = args.port or cfg.auth.bind_port

    log.info("turbobond %s starting on http://%s:%d", __version__, host, port)
    log.info("sign in there; activation runs by itself")

    uvicorn.run(
        create_app(cfg),
        host=host,
        port=port,
        log_level=cfg.log_level.lower(),
        access_log=False,
    )
    return 0


def cmd_up(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.supervisor import Supervisor

    async def _run() -> int:
        supervisor = Supervisor(cfg)
        result = await supervisor.activate(install_dependencies=not args.no_install)
        _dump(result)
        if result.get("error"):
            return 1
        # Keep the monitors alive; activation is not a one-shot.
        log.info("bond is up. Press Ctrl-C to tear it down.")
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await supervisor.deactivate()
        return 0

    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        return 0


def cmd_down(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.bond import mptcp, routing
    from turbobond.lan.gateway import LanGateway
    from turbobond.links.discovery import discover_links
    from turbobond.sip.firewall import SipFirewall

    links = discover_links(cfg)
    SipFirewall(cfg.sip).teardown()
    LanGateway(cfg.lan, cfg.routes, cfg.shadowsocks, cfg.sip).teardown()
    routing.teardown(links)
    mptcp.flush()
    log.info("torn down")
    return 0


def cmd_status(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.bond import mptcp, routing
    from turbobond.links.discovery import discover_links
    from turbobond.sip.firewall import SipFirewall

    links = discover_links(cfg)
    firewall = SipFirewall(cfg.sip)
    _dump(
        {
            "version": __version__,
            "profile": cfg.optimization.profile,
            "links": [link.as_dict() for link in links],
            "routing": routing.current_state(),
            "mptcp": mptcp.state().as_dict(),
            "sip": firewall.verify(),
            "routes": cfg.available_routes(),
        }
    )
    return 0


def cmd_preflight(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.preflight import run_preflight

    report = run_preflight(cfg, install=args.install)
    markers = {"ok": "  ok  ", "degraded": " warn ", "blocking": "BLOCK "}
    for check in report.checks:
        print(f"[{markers.get(check.severity, '  ??  ')}] {check.name}: {check.detail}")
        if check.remedy and check.severity != "ok":
            print(f"          -> {check.remedy}")
    print()
    print(f"{len(report.blocking)} blocking, {len(report.degraded)} degraded")
    return 0 if report.ok else 1


def cmd_links(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.links.discovery import discover_links

    links = discover_links(cfg)
    _dump([link.as_dict() for link in links])
    return 0


def cmd_routes(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.transport.profiles import describe_routes

    _dump(
        {
            "available": describe_routes(),
            "enabled": cfg.available_routes(),
            "default": cfg.routes.default_route,
        }
    )
    return 0


def cmd_sip(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.sip.firewall import SipFirewall

    firewall = SipFirewall(cfg.sip)
    if args.show or not args.apply:
        print(firewall.build_nft_ruleset())
    if args.apply:
        report = firewall.apply()
        _dump(report.as_dict())
        return 0 if report.ok else 1
    return 0


def cmd_config(args: argparse.Namespace, cfg: AppConfig) -> int:
    if args.init:
        path = save_config(cfg)
        print(f"wrote {path}")
        return 0
    _dump(cfg.redacted())
    return 0


def cmd_gen_psk(args: argparse.Namespace, cfg: AppConfig) -> int:
    from turbobond.util.crypto import generate_psk

    print(generate_psk())
    return 0


COMMANDS = {
    "serve": cmd_serve,
    "up": cmd_up,
    "down": cmd_down,
    "status": cmd_status,
    "preflight": cmd_preflight,
    "links": cmd_links,
    "routes": cmd_routes,
    "sip": cmd_sip,
    "config": cmd_config,
    "gen-psk": cmd_gen_psk,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = _load(args)
    except TurboBondError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.remedy:
            print(f"  {exc.remedy}", file=sys.stderr)
        return 2

    handler = COMMANDS[args.command]
    try:
        return handler(args, cfg)
    except TurboBondError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.remedy:
            print(f"  {exc.remedy}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":  # pragma: no cover
    with contextlib.suppress(KeyboardInterrupt):
        raise SystemExit(main())
