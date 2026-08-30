"""Shared builders for the test-suite."""

from __future__ import annotations

from turbobond.links.model import Link, LinkState


def make_link(
    name: str,
    *,
    link_id: int = 1,
    weight: float = 1.0,
    rtt_ms: float = 20.0,
    loss_pct: float = 0.0,
    uplink_mbps: float = 0.0,
    state: LinkState = LinkState.UP,
    metered: bool = False,
    ready: bool = True,
) -> Link:
    link = Link(
        name=name,
        interface=name,
        gateway="10.0.0.1",
        source_ip=f"10.0.{link_id}.2",
        weight=weight,
        uplink_mbps=uplink_mbps,
        downlink_mbps=uplink_mbps,
        metered=metered,
        table_id=200 + link_id,
        link_id=link_id,
        state=state,
    )
    link.health.rtt_ms = rtt_ms
    link.health.loss_pct = loss_pct
    link.tunnel_ready = ready
    return link


def build_ipv4(src_port: int, dst_port: int, *, protocol: int = 17, body: bytes = b"payload") -> bytes:
    """Minimal but structurally valid IPv4 datagram."""

    header = bytearray(20)
    header[0] = 0x45  # version 4, IHL 5
    header[9] = protocol
    header[12:16] = bytes([10, 0, 0, 1])
    header[16:20] = bytes([10, 0, 0, 2])
    transport = src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big") + b"\x00" * 4
    return bytes(header) + transport + body


def build_ipv6(src_port: int, dst_port: int, *, protocol: int = 17) -> bytes:
    header = bytearray(40)
    header[0] = 0x60  # version 6
    header[6] = protocol
    transport = src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big") + b"\x00" * 4
    return bytes(header) + transport
