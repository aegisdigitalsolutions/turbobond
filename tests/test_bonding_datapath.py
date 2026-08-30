"""Proves the bond actually moves packets across several uplinks at once.

A real concentrator is started on loopback and a real client tunnel is pointed
at it. Both ends use simulated TUN devices (so no CAP_NET_ADMIN is needed) but
everything between them is genuine: real UDP sockets, real AEAD framing, the
real scheduler and the real reorder buffer.

This is the claim the whole project rests on, so it is tested end to end rather
than by mocking the datapath.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from helpers import build_ipv4, make_link

from turbobond.bond.server import ConcentratorServer
from turbobond.bond.tunnel import BondingTunnel
from turbobond.config import ConcentratorConfig, SipConfig
from turbobond.util.crypto import generate_psk

PSK = generate_psk()
REORDER_MS = 25.0


async def settle(seconds: float = 0.35) -> None:
    """Let the asyncio datapath tasks run."""

    await asyncio.sleep(seconds)


@pytest.fixture
async def concentrator():
    server = ConcentratorServer(
        PSK,
        host="127.0.0.1",
        port=0,  # replaced below with the port the kernel actually assigned
        tun_name="tbond-test-srv",
        reorder_timeout_ms=REORDER_MS,
    )
    await server.start()
    # Discover the bound port so the client can be pointed at it.
    sock = server._transport.get_extra_info("socket")
    server.port = sock.getsockname()[1]
    yield server
    await server.stop()


@pytest.fixture
async def tunnel(concentrator: ConcentratorServer):
    cfg = ConcentratorConfig(
        enabled=True,
        host="127.0.0.1",
        port=concentrator.port,
        psk_hex=PSK,
        tun_device="tbond-test-cli",
        reorder_timeout_ms=REORDER_MS,
        keepalive_s=0.2,
    )
    links = [
        make_link("wan1", link_id=1, weight=1.0),
        make_link("wan2", link_id=2, weight=1.0),
        make_link("wan3", link_id=3, weight=1.0),
    ]
    client = BondingTunnel(cfg, links, sip=SipConfig())
    await client.start()
    yield client
    with contextlib.suppress(Exception):
        await client.stop()


class TestUpstream:
    async def test_a_packet_sent_into_the_bond_arrives_at_the_concentrator(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        packet = build_ipv4(40000, 443, body=b"hello-across-the-bond")
        tunnel.device.inject_for_test(packet)
        await settle()

        assert packet in concentrator.device.drain_for_test()

    async def test_a_burst_arrives_complete_and_in_order(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        """Spreading one flow over three links must not lose or reorder it."""

        packets = [build_ipv4(40000, 443, body=f"packet-{i:04d}".encode()) for i in range(120)]
        for packet in packets:
            tunnel.device.inject_for_test(packet)
        await settle(1.2)

        assert concentrator.device.drain_for_test() == packets

    async def test_the_burst_was_genuinely_spread_across_every_uplink(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        """Aggregation, not failover: all three sockets must carry traffic."""

        for i in range(150):
            tunnel.device.inject_for_test(build_ipv4(40000, 443, body=f"p{i}".encode()))
        await settle(1.2)

        carried = {sock["link"]: sock["tx_packets"] for sock in tunnel.snapshot()["sockets"]}
        assert len(carried) == 3
        assert all(count > 10 for count in carried.values()), carried

        # And the concentrator saw them arrive from three separate sources.
        session = next(iter(concentrator.sessions.values()))
        assert len(session.links) == 3
        assert all(peer.rx_packets > 10 for peer in session.links.values())

    async def test_each_uplink_uses_a_distinct_source_port(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        """Separate sockets are what let the kernel pin each to its own link."""

        tunnel.device.inject_for_test(build_ipv4(40000, 443, body=b"x"))
        await settle(0.6)
        session = next(iter(concentrator.sessions.values()))
        ports = {peer.addr[1] for peer in session.links.values()}
        assert len(ports) == len(session.links)


class TestDownstream:
    async def test_return_traffic_reaches_the_client(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        # Bring the session up so the concentrator knows where to send replies.
        tunnel.device.inject_for_test(build_ipv4(40000, 443, body=b"open"))
        await settle(0.5)
        concentrator.device.drain_for_test()

        replies = [build_ipv4(443, 40000, body=f"reply-{i:03d}".encode()) for i in range(40)]
        for reply in replies:
            concentrator.device.inject_for_test(reply)
        await settle(1.2)

        assert tunnel.device.drain_for_test() == replies

    async def test_return_traffic_is_spread_over_the_clients_links(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        """Download aggregation only works if the far end fans out too."""

        tunnel.device.inject_for_test(build_ipv4(40000, 443, body=b"open"))
        await settle(0.5)

        for i in range(60):
            concentrator.device.inject_for_test(build_ipv4(443, 40000, body=f"r{i}".encode()))
        await settle(1.2)

        session = next(iter(concentrator.sessions.values()))
        assert all(peer.tx_packets > 5 for peer in session.links.values())


class TestSecurity:
    async def test_datagrams_signed_with_another_key_are_dropped(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        from turbobond.bond.protocol import FrameType, encode_frame
        from turbobond.util.crypto import Sealer

        tunnel.device.inject_for_test(build_ipv4(40000, 443, body=b"open"))
        await settle(0.5)
        concentrator.device.drain_for_test()

        before = concentrator._rejected
        forged = encode_frame(
            Sealer.from_psk(generate_psk()),
            frame_type=FrameType.DATA,
            session_id=0xAAAA,
            link_id=1,
            counter=1,
            seq=1,
            payload=build_ipv4(1, 2, body=b"forged"),
        )
        sock = concentrator._transport.get_extra_info("socket")
        loop = asyncio.get_running_loop()
        spoof = asyncio.DatagramProtocol()
        transport, _ = await loop.create_datagram_endpoint(lambda: spoof, local_addr=("127.0.0.1", 0))
        transport.sendto(forged, sock.getsockname())
        await settle(0.4)
        transport.close()

        assert concentrator._rejected > before
        assert concentrator.device.drain_for_test() == []

    async def test_a_replayed_datagram_is_dropped(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        from turbobond.bond.protocol import FrameType, encode_frame
        from turbobond.util.crypto import Sealer

        sealer = Sealer.from_psk(PSK)
        payload = build_ipv4(40000, 443, body=b"replay-me")
        datagram = encode_frame(
            sealer,
            frame_type=FrameType.DATA,
            session_id=0xBEEF,
            link_id=9,
            counter=1,
            seq=1,
            payload=payload,
        )

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
        )
        target = concentrator._transport.get_extra_info("socket").getsockname()
        transport.sendto(datagram, target)
        await settle(0.3)
        before = concentrator._rejected
        transport.sendto(datagram, target)
        await settle(0.3)
        transport.close()

        assert concentrator._rejected > before


class TestSessionLifecycle:
    async def test_the_concentrator_learns_every_uplink(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        await settle(0.6)  # keepalives alone are enough to register the links
        assert len(concentrator.sessions) == 1
        session = next(iter(concentrator.sessions.values()))
        assert set(session.links) == {1, 2, 3}

    async def test_a_carrier_nat_rebind_is_followed(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        """Mobile carriers rotate source ports; the session must survive it."""

        await settle(0.6)
        session = next(iter(concentrator.sessions.values()))
        peer = session.links[1]
        original = peer.addr

        concentrator.handle_datagram(
            _frame_for(session.session_id, link_id=1, counter=peer.replay.highest + 50),
            ("127.0.0.1", original[1] + 1),
        )
        assert session.links[1].addr != original

    async def test_snapshot_reports_the_live_session(
        self, concentrator: ConcentratorServer, tunnel: BondingTunnel
    ) -> None:
        await settle(0.6)
        snapshot = concentrator.snapshot()
        assert len(snapshot["sessions"]) == 1
        assert len(snapshot["sessions"][0]["links"]) == 3


def _frame_for(session_id: int, *, link_id: int, counter: int) -> bytes:
    from turbobond.bond.protocol import FrameType, encode_frame
    from turbobond.util.crypto import Sealer

    return encode_frame(
        Sealer.from_psk(PSK),
        frame_type=FrameType.KEEPALIVE,
        session_id=session_id,
        link_id=link_id,
        counter=counter,
    )
