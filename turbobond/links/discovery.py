"""Find every usable WAN uplink without the user having to name one.

The kernel already knows which interfaces have a default route and which source
address they use; we read that (via ``ip -j``, falling back to ``/proc`` parsing)
and turn it into :class:`~turbobond.links.model.Link` objects.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
from typing import Any

from turbobond.config import AppConfig, LinkConfig
from turbobond.links.model import Link, LinkState
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("links.discovery")

# Interfaces that are never uplinks.
EXCLUDED_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "tbond", "tun", "tap", "wg", "ppp-mgmt")

# Interface name prefixes ranked by how much we want them carrying traffic.
PREFERENCE = (
    ("eth", 3.0),
    ("en", 3.0),
    ("wl", 2.0),
    ("wwan", 1.5),
    ("wwp", 1.5),
    ("usb", 1.5),
    ("ww", 1.5),
    ("ppp", 1.0),
)


def _is_excluded(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def _preference(name: str) -> float:
    for prefix, weight in PREFERENCE:
        if name.startswith(prefix):
            return weight
    return 1.0


def _guess_metered(name: str) -> bool:
    """Cellular interfaces are assumed metered until told otherwise."""

    return name.startswith(("wwan", "wwp", "ww", "ppp", "usb"))


def list_interfaces() -> list[str]:
    """Every non-excluded network interface currently present."""

    if is_dry_run():
        return ["eth0", "eth1", "wwan0"]
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    return [n for n in names if not _is_excluded(n)]


def read_routes() -> list[dict[str, Any]]:
    """Parse the main routing table.

    Prefers ``ip -j route``; falls back to ``/proc/net/route`` so discovery still
    works on minimal systems that ship without iproute2's JSON support.
    """

    if is_dry_run():
        return [
            {"dst": "default", "dev": "eth0", "gateway": "192.168.1.1", "prefsrc": "192.168.1.50", "metric": 100},
            {"dst": "default", "dev": "eth1", "gateway": "192.168.2.1", "prefsrc": "192.168.2.50", "metric": 200},
            {"dst": "default", "dev": "wwan0", "gateway": "192.168.3.1", "prefsrc": "192.168.3.50", "metric": 300},
        ]

    if which("ip"):
        result = run(["ip", "-j", "route", "show"], quiet=True, allow_missing=True)
        if result.ok and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    return [r for r in data if isinstance(r, dict)]
            except json.JSONDecodeError:
                log.debug("ip -j route produced non-JSON output; falling back to /proc")

    return _read_proc_routes()


def _read_proc_routes() -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    try:
        with open("/proc/net/route") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return routes

    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, dest_hex, gw_hex = fields[0], fields[1], fields[2]
        try:
            dest = socket.inet_ntoa(struct.pack("<L", int(dest_hex, 16)))
            gateway = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
            metric = int(fields[6])
        except (ValueError, struct.error, OSError):
            continue
        routes.append(
            {
                "dst": "default" if dest == "0.0.0.0" else dest,
                "dev": iface,
                "gateway": "" if gateway == "0.0.0.0" else gateway,
                "metric": metric,
            }
        )
    return routes


def interface_address(interface: str) -> str:
    """Primary IPv4 address of an interface."""

    if is_dry_run():
        return {"eth0": "192.168.1.50", "eth1": "192.168.2.50", "wwan0": "192.168.3.50"}.get(interface, "")

    if which("ip"):
        result = run(["ip", "-j", "-4", "addr", "show", "dev", interface], quiet=True, allow_missing=True)
        if result.ok and result.stdout.strip():
            try:
                for entry in json.loads(result.stdout):
                    for addr in entry.get("addr_info", []):
                        if addr.get("family") == "inet" and addr.get("local"):
                            return str(addr["local"])
            except (json.JSONDecodeError, TypeError):
                pass

    try:
        import fcntl

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = struct.pack("256s", interface.encode()[:15])
            return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, packed)[20:24])  # SIOCGIFADDR
    except (OSError, ImportError, ValueError):
        return ""


def _operstate(interface: str) -> LinkState:
    if is_dry_run():
        return LinkState.UP
    try:
        with open(f"/sys/class/net/{interface}/operstate") as fh:
            state = fh.read().strip()
    except OSError:
        return LinkState.DOWN
    if state == "up":
        return LinkState.UP
    if state == "unknown":
        # Point-to-point and modem interfaces often report "unknown" while working.
        return LinkState.UP if interface_address(interface) else LinkState.DOWN
    return LinkState.DOWN


def _interface_speed_mbps(interface: str) -> float:
    """Negotiated link speed, when the driver reports one."""

    if is_dry_run():
        return 1000.0
    try:
        with open(f"/sys/class/net/{interface}/speed") as fh:
            speed = int(fh.read().strip())
        return float(speed) if speed > 0 else 0.0
    except (OSError, ValueError):
        return 0.0


def discover_links(cfg: AppConfig) -> list[Link]:
    """Build the link set from configuration plus autodiscovery.

    Explicitly configured links always win; autodiscovery only adds uplinks that
    were not named in the config.
    """

    links: list[Link] = []
    seen_interfaces: set[str] = set()

    for lc in cfg.links:
        link = Link(
            name=lc.name,
            interface=lc.interface,
            gateway=lc.gateway,
            weight=lc.weight,
            uplink_mbps=lc.uplink_mbps,
            downlink_mbps=lc.downlink_mbps,
            metered=lc.metered,
            enabled=lc.enabled,
            table_id=lc.table_id,
        )
        link.source_ip = interface_address(lc.interface)
        link.state = _operstate(lc.interface) if lc.enabled else LinkState.DISABLED
        links.append(link)
        seen_interfaces.add(lc.interface)

    if cfg.auto_discover_links:
        for link in _autodiscover(exclude=seen_interfaces):
            links.append(link)
            seen_interfaces.add(link.interface)

    for lc, link in zip(cfg.links, links, strict=False):
        if not link.gateway:
            link.gateway = lc.gateway

    _assign_ids(links)
    _fill_missing_gateways(links)

    usable = [link for link in links if link.usable]
    log.info(
        "discovered %d uplink(s), %d usable: %s",
        len(links),
        len(usable),
        ", ".join(f"{link.name}({link.interface})" for link in links) or "none",
    )
    return links


def _autodiscover(exclude: set[str]) -> list[Link]:
    routes = read_routes()
    defaults: dict[str, dict[str, Any]] = {}
    for route in routes:
        if route.get("dst") not in ("default", "0.0.0.0/0"):
            continue
        dev = str(route.get("dev") or "")
        if not dev or dev in exclude or _is_excluded(dev):
            continue
        # Keep the lowest-metric default route per interface.
        existing = defaults.get(dev)
        if existing is None or int(route.get("metric") or 0) < int(existing.get("metric") or 0):
            defaults[dev] = route

    links: list[Link] = []
    for dev, route in sorted(defaults.items()):
        source = str(route.get("prefsrc") or "") or interface_address(dev)
        state = _operstate(dev)
        if state is LinkState.DOWN:
            log.debug("skipping %s: interface is down", dev)
            continue
        speed = _interface_speed_mbps(dev)
        links.append(
            Link(
                name=dev,
                interface=dev,
                gateway=str(route.get("gateway") or ""),
                source_ip=source,
                weight=_preference(dev),
                uplink_mbps=speed,
                downlink_mbps=speed,
                metered=_guess_metered(dev),
                enabled=True,
                state=state,
            )
        )
    return links


def _assign_ids(links: list[Link]) -> None:
    """Stable per-link ids: table ids for policy routing, link ids for the wire."""

    used_tables = {link.table_id for link in links if link.table_id}
    next_table = 200
    for index, link in enumerate(links, start=1):
        if not link.table_id:
            while next_table in used_tables:
                next_table += 1
            link.table_id = next_table
            used_tables.add(next_table)
            next_table += 1
        if not link.link_id:
            link.link_id = index


def _fill_missing_gateways(links: list[Link]) -> None:
    routes = read_routes()
    by_dev: dict[str, str] = {}
    for route in routes:
        if route.get("dst") in ("default", "0.0.0.0/0") and route.get("gateway"):
            by_dev.setdefault(str(route["dev"]), str(route["gateway"]))
    for link in links:
        if not link.gateway:
            link.gateway = by_dev.get(link.interface, "")
        if not link.source_ip:
            link.source_ip = interface_address(link.interface)
        if link.gateway and not _valid_ip(link.gateway):
            log.warning("link %s has an unparseable gateway %r; ignoring it", link.name, link.gateway)
            link.gateway = ""


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def links_to_config(links: list[Link]) -> list[LinkConfig]:
    """Persist discovered links back into config form."""

    return [
        LinkConfig(
            name=link.name,
            interface=link.interface,
            gateway=link.gateway,
            weight=link.weight,
            uplink_mbps=link.uplink_mbps,
            downlink_mbps=link.downlink_mbps,
            metered=link.metered,
            enabled=link.enabled,
            table_id=link.table_id,
        )
        for link in links
    ]
