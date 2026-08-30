"""Dependency and capability checks run before activation.

Every check reports one of three outcomes:

``ok``
    Present and usable.
``degraded``
    Missing, but turbobond has a working fallback, so activation continues.
``blocking``
    Activation cannot proceed until it is resolved.

With ``install=True`` the missing system packages are installed automatically,
which is what lets the user do nothing but sign in.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Literal

from turbobond.config import AppConfig
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("preflight")

Severity = Literal["ok", "degraded", "blocking"]


@dataclass
class Check:
    name: str
    severity: Severity
    detail: str
    remedy: str = ""
    fixable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "detail": self.detail,
            "remedy": self.remedy,
            "fixable": self.fixable,
        }


@dataclass
class PreflightReport:
    checks: list[Check] = field(default_factory=list)
    installed: list[str] = field(default_factory=list)

    @property
    def blocking(self) -> list[Check]:
        return [c for c in self.checks if c.severity == "blocking"]

    @property
    def degraded(self) -> list[Check]:
        return [c for c in self.checks if c.severity == "degraded"]

    @property
    def ok(self) -> bool:
        return not self.blocking

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "blocking": len(self.blocking),
            "degraded": len(self.degraded),
            "installed": self.installed,
            "checks": [c.as_dict() for c in self.checks],
        }


# Executable -> (package name, severity when missing, what we lose).
REQUIRED_TOOLS: dict[str, tuple[str, Severity, str]] = {
    "ip": ("iproute2", "blocking", "policy routing, MPTCP and the tunnel interface all need iproute2"),
    "nft": ("nftables", "degraded", "falls back to iptables for the SIP and NAT rules"),
    "iptables": ("iptables", "degraded", "only needed when nftables is unavailable"),
    "tc": ("iproute2", "degraded", "voice prioritisation is skipped without tc"),
    "sysctl": ("procps", "degraded", "kernel tuning is skipped without sysctl"),
    "ping": ("iputils-ping", "degraded", "link probing falls back to TCP handshakes"),
    "sslocal": ("shadowsocks-rust", "degraded", "the shadow route needs a shadowsocks client"),
}

PACKAGE_MANAGERS: list[tuple[str, list[str], list[str]]] = [
    ("apt-get", ["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "--no-install-recommends"]),
    ("dnf", [], ["dnf", "install", "-y"]),
    ("yum", [], ["yum", "install", "-y"]),
    ("apk", [], ["apk", "add", "--no-cache"]),
    ("pacman", [], ["pacman", "-S", "--noconfirm"]),
    ("opkg", ["opkg", "update"], ["opkg", "install"]),
]


def detect_package_manager() -> tuple[str, list[str], list[str]] | None:
    for name, update, install in PACKAGE_MANAGERS:
        if which(name):
            return name, update, install
    return None


def install_packages(packages: list[str]) -> list[str]:
    """Install system packages with whatever package manager exists."""

    if not packages:
        return []
    if is_dry_run():
        log.info("[dry-run] would install: %s", ", ".join(packages))
        return list(packages)

    manager = detect_package_manager()
    if manager is None:
        log.warning("no supported package manager found; cannot install %s", ", ".join(packages))
        return []

    name, update_argv, install_argv = manager
    log.info("installing with %s: %s", name, ", ".join(packages))
    if update_argv:
        run(update_argv, timeout=300, allow_missing=True)
    result = run([*install_argv, *packages], timeout=900, allow_missing=True)
    if not result.ok:
        log.warning("package installation reported an error: %s", result.stderr.strip().splitlines()[:1])
    return [p for p in packages if which(_binary_for(p)) or p == "shadowsocks-rust"]


def _binary_for(package: str) -> str:
    return {
        "iproute2": "ip",
        "nftables": "nft",
        "iptables": "iptables",
        "procps": "sysctl",
        "iputils-ping": "ping",
        "shadowsocks-rust": "sslocal",
        "shadowsocks-libev": "ss-local",
    }.get(package, package)


def check_privileges() -> Check:
    if is_dry_run():
        return Check("privileges", "ok", "dry-run mode does not need privileges")
    if os.geteuid() == 0:
        return Check("privileges", "ok", "running as root")
    return Check(
        "privileges",
        "blocking",
        "turbobond is not running as root",
        remedy="Start it with sudo or as a systemd service; it programs routing, firewall and tunnel state.",
    )


def check_tun() -> Check:
    if is_dry_run():
        return Check("tun_device", "ok", "simulated in dry-run mode")
    if os.path.exists("/dev/net/tun"):
        return Check("tun_device", "ok", "/dev/net/tun is present")
    result = run(["modprobe", "tun"], quiet=True, allow_missing=True)
    if result.ok and os.path.exists("/dev/net/tun"):
        return Check("tun_device", "ok", "tun module loaded")
    return Check(
        "tun_device",
        "degraded",
        "/dev/net/tun is missing, so packet-level bonding is unavailable",
        remedy="Load the tun module ('modprobe tun'). Without it turbobond uses weighted ECMP instead.",
        fixable=True,
    )


def check_mptcp() -> Check:
    if is_dry_run() or os.path.exists("/proc/sys/net/mptcp/enabled"):
        return Check("mptcp", "ok", "kernel supports Multipath TCP")
    return Check(
        "mptcp",
        "degraded",
        "this kernel has no MPTCP support",
        remedy="Linux 5.6 or newer adds MPTCP. Bonding still works through the tunnel without it.",
    )


def check_conntrack_capacity() -> Check:
    if is_dry_run():
        return Check("conntrack", "ok", "dry-run")
    path = "/proc/sys/net/netfilter/nf_conntrack_max"
    if not os.path.exists(path):
        return Check("conntrack", "degraded", "connection tracking is not loaded yet")
    try:
        with open(path) as fh:
            value = int(fh.read().strip())
    except (OSError, ValueError):
        return Check("conntrack", "degraded", "could not read the conntrack limit")
    if value < 262144:
        return Check(
            "conntrack",
            "degraded",
            f"conntrack table holds only {value} flows",
            remedy="Activation raises this automatically as part of the turbo profile.",
            fixable=True,
        )
    return Check("conntrack", "ok", f"conntrack table holds {value} flows")


def check_uplinks(cfg: AppConfig) -> Check:
    from turbobond.links.discovery import discover_links

    links = discover_links(cfg)
    usable = [link for link in links if link.usable]
    if not usable:
        return Check(
            "uplinks",
            "blocking",
            "no usable WAN uplink was found",
            remedy="Connect at least one WAN interface, or list them under 'links' in the config.",
        )
    if len(usable) == 1:
        return Check(
            "uplinks",
            "degraded",
            f"only one uplink ({usable[0].name}) is available, so there is nothing to bond yet",
            remedy="Attach a second WAN connection; turbobond will pick it up and add it to the bond.",
        )
    return Check("uplinks", "ok", f"{len(usable)} uplinks available for bonding: " + ", ".join(u.name for u in usable))


def check_concentrator(cfg: AppConfig) -> Check:
    if cfg.concentrator.enabled and cfg.concentrator.host:
        return Check("concentrator", "ok", f"bonding concentrator configured at {cfg.concentrator.host}")
    return Check(
        "concentrator",
        "degraded",
        "no bonding concentrator is configured, so aggregation runs in local mode",
        remedy=(
            "Packet-level bonding of a single connection needs a peer to reassemble the stream. "
            "Deploy 'turbobond-server' on a VPS and set concentrator.host to unlock it. "
            "Until then turbobond uses weighted ECMP plus MPTCP, which aggregates across flows."
        ),
    )


def check_shadowsocks(cfg: AppConfig) -> Check:
    if not cfg.shadowsocks.enabled:
        return Check("shadowsocks", "ok", "the shadow route is turned off")
    if not cfg.shadowsocks.usable:
        return Check(
            "shadowsocks",
            "degraded",
            "the shadow route has no server configured, so only the direct route is usable",
            remedy="Enter the shadowsocks server, port and password on the sign-in screen.",
        )
    if not (which("sslocal") or which("ss-local") or is_dry_run()):
        return Check(
            "shadowsocks",
            "degraded",
            "no shadowsocks client binary is installed",
            remedy="Activation installs one automatically; run preflight with --install to do it now.",
            fixable=True,
        )
    return Check("shadowsocks", "ok", f"shadow route ready via {cfg.shadowsocks.host}:{cfg.shadowsocks.port}")


#: Below this, `StrEnum`, `asyncio.TimeoutError` aliasing and `sock_sendto` are absent.
MINIMUM_PYTHON = (3, 11)


def check_python() -> Check:
    running = (sys.version_info.major, sys.version_info.minor)
    if running >= MINIMUM_PYTHON:
        return Check("python", "ok", f"Python {running[0]}.{running[1]}")
    required = f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]}"
    return Check(
        "python",
        "blocking",
        f"Python {running[0]}.{running[1]} is too old",
        remedy=f"turbobond needs Python {required} or newer.",
    )


def check_router(cfg: AppConfig) -> Check:
    if not cfg.router.manage:
        return Check("router", "ok", "router management is turned off")
    if not cfg.router.password:
        return Check(
            "router",
            "degraded",
            "no router administrator password is set, so the router runs read-only",
            remedy="Enter the router admin password on the sign-in screen to let the app configure it.",
        )
    return Check("router", "ok", f"router web administrator at {cfg.router.base_url}")


def run_preflight(cfg: AppConfig, *, install: bool = False) -> PreflightReport:
    """Run every check, optionally installing what is missing."""

    report = PreflightReport()
    report.checks.append(check_python())
    report.checks.append(check_privileges())

    missing_packages: list[str] = []
    for binary, (package, severity, detail) in REQUIRED_TOOLS.items():
        if which(binary) or is_dry_run():
            report.checks.append(Check(f"tool:{binary}", "ok", f"{binary} is installed"))
            continue
        missing_packages.append(package)
        report.checks.append(
            Check(
                f"tool:{binary}",
                severity,
                f"{binary} is not installed: {detail}",
                remedy=f"Install the '{package}' package.",
                fixable=True,
            )
        )

    if install and missing_packages:
        report.installed = install_packages(sorted(set(missing_packages)))
        # Re-check whatever we just installed.
        for check in report.checks:
            if check.name.startswith("tool:"):
                binary = check.name.split(":", 1)[1]
                if which(binary):
                    check.severity = "ok"
                    check.detail = f"{binary} installed by turbobond"
                    check.remedy = ""

    report.checks.append(check_tun())
    report.checks.append(check_mptcp())
    report.checks.append(check_conntrack_capacity())
    report.checks.append(check_router(cfg))
    report.checks.append(check_uplinks(cfg))
    report.checks.append(check_concentrator(cfg))
    report.checks.append(check_shadowsocks(cfg))

    blocking = report.blocking
    if blocking:
        log.warning("preflight found %d blocking issue(s): %s", len(blocking), ", ".join(c.name for c in blocking))
    else:
        log.info("preflight passed (%d degraded check(s))", len(report.degraded))
    return report


def python_dependencies_present() -> list[str]:
    """Import-check the third-party packages the app needs at runtime."""

    missing: list[str] = []
    for module, package in (
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("pydantic", "pydantic"),
        ("httpx", "httpx"),
        ("yaml", "PyYAML"),
        ("cryptography", "cryptography"),
        ("argon2", "argon2-cffi"),
        ("itsdangerous", "itsdangerous"),
    ):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    return missing


def install_python_dependencies(packages: list[str]) -> bool:
    if not packages:
        return True
    if is_dry_run():
        log.info("[dry-run] would pip install %s", " ".join(packages))
        return True
    pip = shutil.which("pip3") or shutil.which("pip")
    if pip is None:
        log.warning("pip is not available, so Python dependencies cannot be installed automatically")
        return False
    result = run([pip, "install", "--upgrade", *packages], timeout=900, allow_missing=True)
    return result.ok
