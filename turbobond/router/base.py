"""Router-agnostic interface the rest of turbobond programs against."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(slots=True)
class ConnectedDevice:
    """A client attached to the router's LAN/WLAN."""

    mac: str
    ip: str = ""
    name: str = ""
    connection: str = ""  # "wifi-2.4", "wifi-5", "wifi-6", "ethernet", "usb"
    rssi: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    bonded: bool = False

    def key(self) -> str:
        return (self.mac or self.ip).lower()

    def as_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "name": self.name,
            "connection": self.connection,
            "rssi": self.rssi,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "bonded": self.bonded,
        }


@dataclass(slots=True)
class RouterStatus:
    """Snapshot of the router's WAN/radio state."""

    reachable: bool = False
    authenticated: bool = False
    model: str = ""
    firmware: str = ""
    serial: str = ""
    lan_ip: str = ""
    wan_ip: str = ""
    wan_state: str = ""
    carrier: str = ""
    network_type: str = ""  # "5G-NSA", "5G-SA", "LTE", "ethernet"
    bands: list[str] = field(default_factory=list)
    rssi: int | None = None
    rsrp: int | None = None
    rsrq: int | None = None
    sinr: float | None = None
    battery_pct: int | None = None
    uptime_s: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    sip_alg_enabled: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = {
            "reachable": self.reachable,
            "authenticated": self.authenticated,
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "lan_ip": self.lan_ip,
            "wan_ip": self.wan_ip,
            "wan_state": self.wan_state,
            "carrier": self.carrier,
            "network_type": self.network_type,
            "bands": self.bands,
            "rssi": self.rssi,
            "rsrp": self.rsrp,
            "rsrq": self.rsrq,
            "sinr": self.sinr,
            "battery_pct": self.battery_pct,
            "uptime_s": self.uptime_s,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "sip_alg_enabled": self.sip_alg_enabled,
            "error": self.error,
        }
        return data


@runtime_checkable
class RouterAdmin(Protocol):
    """Everything turbobond needs from a router's administrative interface."""

    async def connect(self) -> RouterStatus:
        """Open a session (log in) and return the current status."""

    async def status(self) -> RouterStatus:
        """Refresh status using the existing session."""

    async def devices(self) -> list[ConnectedDevice]:
        """List devices currently attached to the router."""

    async def set_values(self, values: dict[str, Any]) -> dict[str, bool]:
        """Write configuration keys. Returns per-key success."""

    async def set_sip_alg(self, enabled: bool) -> bool:
        """Enable/disable the router's SIP application-layer gateway."""

    async def apply_optimization(self, profile: dict[str, Any]) -> dict[str, bool]:
        """Push a throughput/latency tuning profile to the router."""

    async def close(self) -> None:
        """Release the session."""
