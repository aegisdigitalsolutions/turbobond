"""The two routes turbobond always offers.

``direct``
    Traffic is bonded across every uplink and leaves at the concentrator (or via
    weighted ECMP when no concentrator is configured). Lowest latency, highest
    throughput, and the route SIP uses.

``shadow``
    The same bond, but the payload is additionally carried inside a shadowsocks
    tunnel before it leaves the concentrator. Costs a little latency and CPU;
    buys an encrypted, protocol-obfuscated egress.

Both routes sit on top of the *same* bond, so choosing between them never
changes how many uplinks are aggregated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RouteName = Literal["direct", "shadow"]


@dataclass(frozen=True, slots=True)
class RouteProfile:
    name: RouteName
    title: str
    description: str
    encrypted: bool
    obfuscated: bool
    # Extra one-way latency this route adds on top of the bond, in milliseconds.
    added_latency_ms: float
    # Fraction of throughput retained relative to the direct route.
    throughput_factor: float
    # Whether SIP is allowed to use it. SIP stays on `direct` because proxying
    # RTP through shadowsocks adds jitter that shows up as choppy audio.
    carries_sip: bool
    requires: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "encrypted": self.encrypted,
            "obfuscated": self.obfuscated,
            "added_latency_ms": self.added_latency_ms,
            "throughput_factor": self.throughput_factor,
            "carries_sip": self.carries_sip,
            "requires": list(self.requires),
        }


DIRECT = RouteProfile(
    name="direct",
    title="Bonded direct",
    description=(
        "All uplinks aggregated into one pipe with no extra proxy hop. "
        "Fastest route and the one voice traffic uses."
    ),
    encrypted=True,  # the bonding tunnel itself is ChaCha20-Poly1305 sealed
    obfuscated=False,
    added_latency_ms=0.0,
    throughput_factor=1.0,
    carries_sip=True,
)

SHADOW = RouteProfile(
    name="shadow",
    title="Bonded + Shadowsocks",
    description=(
        "The same bonded pipe, then wrapped in a shadowsocks tunnel before it "
        "reaches the internet. Adds an encrypted, obfuscated egress."
    ),
    encrypted=True,
    obfuscated=True,
    added_latency_ms=8.0,
    throughput_factor=0.92,
    carries_sip=False,
    requires=("shadowsocks server", "sslocal binary"),
)

ROUTES: dict[str, RouteProfile] = {DIRECT.name: DIRECT, SHADOW.name: SHADOW}


def get_route(name: str) -> RouteProfile:
    profile = ROUTES.get(name)
    if profile is None:
        raise KeyError(f"unknown route {name!r}; available: {', '.join(ROUTES)}")
    return profile


def other_route(name: str) -> RouteProfile:
    """The route to fail over to."""

    return SHADOW if name == DIRECT.name else DIRECT


def describe_routes() -> list[dict[str, Any]]:
    return [profile.as_dict() for profile in ROUTES.values()]
