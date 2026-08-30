"""The two selectable routes and the logic that switches between them."""

from turbobond.transport.profiles import ROUTES, RouteProfile, describe_routes
from turbobond.transport.selector import RouteSelector, RouteStatus
from turbobond.transport.shadowsocks import ShadowsocksManager

__all__ = [
    "ROUTES",
    "RouteProfile",
    "RouteSelector",
    "RouteStatus",
    "ShadowsocksManager",
    "describe_routes",
]
