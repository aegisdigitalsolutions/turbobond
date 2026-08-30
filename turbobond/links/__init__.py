"""WAN uplink discovery, modelling and health monitoring."""

from turbobond.links.discovery import discover_links, list_interfaces, read_routes
from turbobond.links.model import Link, LinkHealth, LinkState
from turbobond.links.monitor import LinkMonitor

__all__ = [
    "Link",
    "LinkHealth",
    "LinkMonitor",
    "LinkState",
    "discover_links",
    "list_interfaces",
    "read_routes",
]
