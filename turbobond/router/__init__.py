"""Router web-administrator integration."""

from turbobond.router.base import ConnectedDevice, RouterAdmin, RouterStatus
from turbobond.router.netgear_m7pro import NighthawkAdmin, build_router_admin

__all__ = [
    "ConnectedDevice",
    "NighthawkAdmin",
    "RouterAdmin",
    "RouterStatus",
    "build_router_admin",
]
