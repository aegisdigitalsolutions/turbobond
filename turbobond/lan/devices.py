"""Tracks every device attached to the network.

Devices are learned from two independent sources - the router's own client list
and the local neighbour table - and merged, so a device shows up whether it is
attached to the router's wifi or plugged into the gateway host directly.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from turbobond.logging_setup import get_logger
from turbobond.router.base import ConnectedDevice
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("lan.devices")

_ARP_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(?P<mac>[0-9a-fA-F:]{17})\s+\S+\s+(?P<dev>\S+)"
)


@dataclass
class TrackedDevice:
    device: ConnectedDevice
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    route: str = "direct"
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = self.device.as_dict()
        data.update(
            {
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "age_s": round(time.time() - self.last_seen, 1),
                "route": self.route,
                "source": self.source,
                "online": (time.time() - self.last_seen) < 300,
            }
        )
        return data


def read_neighbours() -> list[ConnectedDevice]:
    """Devices in the kernel's ARP/neighbour table."""

    if is_dry_run():
        return [
            ConnectedDevice(mac="aa:bb:cc:00:00:01", ip="192.168.1.20", name="", connection="ethernet"),
            ConnectedDevice(mac="aa:bb:cc:00:00:04", ip="192.168.1.30", name="", connection="ethernet"),
        ]

    devices: list[ConnectedDevice] = []
    if which("ip"):
        result = run(["ip", "-j", "neigh", "show"], quiet=True, allow_missing=True)
        if result.ok and result.stdout.strip():
            try:
                for entry in json.loads(result.stdout):
                    if not isinstance(entry, dict):
                        continue
                    mac = str(entry.get("lladdr") or "").lower()
                    ip = str(entry.get("dst") or "")
                    state = [s.upper() for s in entry.get("state", [])]
                    if not mac or "FAILED" in state or "INCOMPLETE" in state:
                        continue
                    devices.append(
                        ConnectedDevice(mac=mac, ip=ip, connection=str(entry.get("dev") or ""))
                    )
                return devices
            except (json.JSONDecodeError, TypeError):
                pass

    try:
        with open("/proc/net/arp") as fh:
            for line in fh.read().splitlines()[1:]:
                match = _ARP_RE.match(line)
                if match:
                    mac = match.group("mac").lower()
                    if mac == "00:00:00:00:00:00":
                        continue
                    devices.append(
                        ConnectedDevice(mac=mac, ip=match.group("ip"), connection=match.group("dev"))
                    )
    except OSError:
        pass
    return devices


class DeviceRegistry:
    """Merged view of everything on the network, and which route each one takes."""

    def __init__(self, *, default_route: str = "direct") -> None:
        self.default_route = default_route
        self._devices: dict[str, TrackedDevice] = {}

    def merge(self, devices: list[ConnectedDevice], *, source: str) -> int:
        """Fold a batch of observations into the registry."""

        added = 0
        now = time.time()
        for device in devices:
            key = device.key()
            if not key:
                continue
            tracked = self._devices.get(key)
            if tracked is None:
                self._devices[key] = TrackedDevice(device=device, source=source, route=self.default_route)
                added += 1
                log.info("device joined: %s (%s) via %s", device.name or device.ip or key, key, source)
                continue
            tracked.last_seen = now
            tracked.source = source
            # Later observations fill in details the earlier source lacked.
            if device.name and not tracked.device.name:
                tracked.device.name = device.name
            if device.ip and not tracked.device.ip:
                tracked.device.ip = device.ip
            if device.connection and not tracked.device.connection:
                tracked.device.connection = device.connection
            if device.rssi is not None:
                tracked.device.rssi = device.rssi
            tracked.device.rx_bytes = max(tracked.device.rx_bytes, device.rx_bytes)
            tracked.device.tx_bytes = max(tracked.device.tx_bytes, device.tx_bytes)
        return added

    def mark_bonded(self, bonded: bool = True) -> None:
        """Flag every known device as riding the bond."""

        for tracked in self._devices.values():
            tracked.device.bonded = bonded

    def set_route(self, key: str, route: str) -> bool:
        tracked = self._devices.get(key.lower())
        if tracked is None or route not in ("direct", "shadow"):
            return False
        tracked.route = route
        log.info("device %s pinned to the %s route", key, route)
        return True

    def route_map(self) -> dict[str, str]:
        """IP -> route, in the form the LAN gateway consumes."""

        return {t.device.ip: t.route for t in self._devices.values() if t.device.ip}

    def online(self, *, within_s: float = 300.0) -> list[TrackedDevice]:
        cutoff = time.time() - within_s
        return [t for t in self._devices.values() if t.last_seen >= cutoff]

    def all(self) -> list[TrackedDevice]:
        return list(self._devices.values())

    def snapshot(self) -> dict[str, Any]:
        online = self.online()
        return {
            "total": len(self._devices),
            "online": len(online),
            "bonded": sum(1 for t in online if t.device.bonded),
            "devices": [t.as_dict() for t in sorted(self._devices.values(), key=lambda t: t.device.ip or "")],
        }
