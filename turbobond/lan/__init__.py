"""Turning the host into the bonded gateway for the whole LAN."""

from turbobond.lan.devices import DeviceRegistry
from turbobond.lan.gateway import LanGateway

__all__ = ["DeviceRegistry", "LanGateway"]
