"""Concentrator: the server half of the bonding tunnel.

Deployed on a host with a single fat uplink (a VPS). It terminates the bonded
session, resequences the packets that arrived across all of the client's links,
and NATs them out to the internet. Return traffic is scheduled back across the
same set of links, which is what makes *download* aggregation work - without a
peer doing this, inbound packets would only ever arrive over whichever single
link the remote server chose.

Run it with ``turbobond-server --psk <hex> --listen 0.0.0.0:5310``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from turbobond.bond import provision, selfcheck
from turbobond.bond.protocol import (
    MAX_DATAGRAM,
    FrameType,
    ReplayWindow,
    decode_frame,
    encode_frame,
)
from turbobond.bond.reorder import ReorderBuffer
from turbobond.bond.tundev import TunDevice
from turbobond.logging_setup import configure as configure_logging
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import run
from turbobond.util.crypto import Sealer, generate_psk

log = get_logger("bond.server")

SESSION_IDLE_TIMEOUT_S = 120.0


@dataclass
class PeerLink:
    """One of a client's uplinks, identified by the address it arrives from."""

    link_id: int
    addr: tuple[str, int]
    counter: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    last_seen: float = field(default_factory=time.time)
    replay: ReplayWindow = field(default_factory=ReplayWindow)

    def next_counter(self) -> int:
        self.counter += 1
        return self.counter

    @property
    def alive(self) -> bool:
        return (time.time() - self.last_seen) < SESSION_IDLE_TIMEOUT_S

    def as_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "addr": f"{self.addr[0]}:{self.addr[1]}",
            "rx_packets": self.rx_packets,
            "tx_packets": self.tx_packets,
            "age_s": round(time.time() - self.last_seen, 1),
            "alive": self.alive,
        }


@dataclass
class Session:
    """A single bonded client."""

    session_id: int
    links: dict[int, PeerLink] = field(default_factory=dict)
    reorder: ReorderBuffer = field(default_factory=lambda: ReorderBuffer(timeout_ms=90.0, capacity=4096))
    seq: int = 0
    created: float = field(default_factory=time.time)
    # Round-robin cursor for spreading return traffic over the client's links.
    cursor: int = 0

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def live_links(self) -> list[PeerLink]:
        return [link for link in self.links.values() if link.alive]

    def pick_return_link(self) -> PeerLink | None:
        """Spread downstream packets across every link the client still has up."""

        live = self.live_links()
        if not live:
            return None
        link = live[self.cursor % len(live)]
        self.cursor += 1
        return link

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": f"{self.session_id:08x}",
            "uptime_s": round(time.time() - self.created, 1),
            "links": [link.as_dict() for link in self.links.values()],
            "reorder": self.reorder.snapshot(),
        }


class ConcentratorServer:
    """UDP listener that terminates bonded sessions."""

    def __init__(
        self,
        psk_hex: str,
        *,
        host: str = "0.0.0.0",
        port: int = 5310,
        tun_name: str = "tbond-srv",
        tunnel_mtu: int = 1380,
        local_cidr: str = "10.77.0.1/30",
        peer_ip: str = "10.77.0.2",
        egress_interface: str = "",
        reorder_timeout_ms: float = 90.0,
    ) -> None:
        self.sealer = Sealer.from_psk(psk_hex)
        self.host = host
        self.port = port
        self.local_cidr = local_cidr
        self.peer_ip = peer_ip
        self.egress_interface = egress_interface
        self.reorder_timeout_ms = reorder_timeout_ms
        self.device = TunDevice(tun_name, mtu=tunnel_mtu)
        self.sessions: dict[int, Session] = {}
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._stop = asyncio.Event()
        self._rejected = 0
        self._rejected_sources: set[str] = set()
        self._firewall_rules: list[list[str]] = []

    # --------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        self.device.open()
        self.device.configure(self.local_cidr, self.peer_ip)
        self._enable_forwarding()

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ServerProtocol(self),
            local_addr=(self.host, self.port),
        )
        self._transport = transport  # type: ignore[assignment]

        self._stop.clear()
        self._tasks = [
            asyncio.create_task(self._tun_reader(), name="tbond-srv-tun"),
            asyncio.create_task(self._reorder_ticker(), name="tbond-srv-reorder"),
            asyncio.create_task(self._reaper(), name="tbond-srv-reaper"),
        ]
        log.info("concentrator listening on %s:%d, tunnel %s", self.host, self.port, self.device.name)

    def _enable_forwarding(self) -> None:
        """Route and masquerade tunnel traffic out to the internet."""

        run(["sysctl", "-w", "net.ipv4.ip_forward=1"], quiet=True, allow_missing=True)
        run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], quiet=True, allow_missing=True)
        egress = self.egress_interface or _default_egress()
        if not egress:
            log.warning("no egress interface found; NAT for tunnel clients was not installed")
            return
        subnet = self.local_cidr.rsplit("/", 1)[0].rsplit(".", 1)[0] + ".0/24"
        # Every rule is recorded so stop() can take it back out again. They are
        # also all inserted through _ensure_rule, because the unit restarts
        # itself on failure: appending unconditionally would add another copy of
        # each rule per restart, and a service that crash-loops would grow the
        # chains without bound.
        self._firewall_rules = [
            ["-t", "nat", "POSTROUTING", "-s", subnet, "-o", egress, "-j", "MASQUERADE"],
            ["FORWARD", "-i", self.device.name, "-o", egress, "-j", "ACCEPT"],
            ["FORWARD", "-i", egress, "-o", self.device.name, "-j", "ACCEPT"],
            # The tunnel MTU is smaller than the egress MTU, so clamp TCP MSS or
            # large flows through the bond will silently blackhole.
            [
                "-t", "mangle", "FORWARD",
                "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                "-j", "TCPMSS", "--clamp-mss-to-pmtu",
            ],
        ]
        for rule in self._firewall_rules:
            self._ensure_rule(rule)
        log.info("NAT installed: %s -> %s", subnet, egress)

    @staticmethod
    def _rule_command(rule: list[str], action: str) -> list[str]:
        """Splice the action in after any '-t <table>' prefix, where iptables wants it."""

        if rule[:1] == ["-t"]:
            return ["iptables", *rule[:2], action, *rule[2:]]
        return ["iptables", action, *rule]

    def _ensure_rule(self, rule: list[str]) -> None:
        if not run(self._rule_command(rule, "-C"), quiet=True, allow_missing=True).ok:
            run(self._rule_command(rule, "-A"), quiet=True, allow_missing=True)

    def _remove_firewall_rules(self) -> None:
        """Take back the rules this process added.

        Leaving NAT for the tunnel subnet in place after the concentrator has
        stopped would quietly masquerade traffic for a tunnel that no longer
        exists.
        """

        for rule in self._firewall_rules:
            run(self._rule_command(rule, "-D"), quiet=True, allow_missing=True)
        self._firewall_rules = []

    async def stop(self) -> None:
        self._stop.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._remove_firewall_rules()
        self.device.teardown()
        log.info("concentrator stopped")

    # ---------------------------------------------------------------- datapath

    def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Client -> internet."""

        frame = decode_frame(self.sealer, data)
        if frame is None:
            self._rejected += 1
            self._note_rejection(addr)
            return

        session = self.sessions.get(frame.session_id)
        if session is None:
            session = Session(
                session_id=frame.session_id,
                reorder=ReorderBuffer(timeout_ms=self.reorder_timeout_ms, capacity=4096),
            )
            self.sessions[frame.session_id] = session
            log.info("new bonded session %08x", frame.session_id)

        peer = session.links.get(frame.link_id)
        if peer is None:
            peer = PeerLink(link_id=frame.link_id, addr=addr)
            session.links[frame.link_id] = peer
            log.info("session %08x: uplink %d joined from %s:%d", frame.session_id, frame.link_id, *addr)
        elif peer.addr != addr:
            # Carrier NAT rebinds ports regularly; follow the client.
            log.info("session %08x uplink %d moved %s -> %s", frame.session_id, frame.link_id, peer.addr, addr)
            peer.addr = addr

        if not peer.replay.check_and_update(frame.counter):
            self._rejected += 1
            return

        peer.last_seen = time.time()
        peer.rx_packets += 1

        if frame.type is FrameType.HANDSHAKE:
            self._send_control(session, peer, FrameType.HANDSHAKE_ACK)
            return
        if frame.type is FrameType.KEEPALIVE:
            self._send_control(session, peer, FrameType.KEEPALIVE)
            return
        if frame.type is FrameType.CLOSE:
            session.links.pop(frame.link_id, None)
            if not session.links:
                self.sessions.pop(frame.session_id, None)
                log.info("session %08x closed", frame.session_id)
            return
        if frame.type is FrameType.DATA and frame.payload:
            for packet in session.reorder.push(frame.seq, frame.payload):
                self.device.write(packet)

    def _send_control(self, session: Session, peer: PeerLink, frame_type: FrameType) -> None:
        self._send(session, peer, frame_type, seq=0, payload=b"")

    def _send(self, session: Session, peer: PeerLink, frame_type: FrameType, *, seq: int, payload: bytes) -> None:
        if self._transport is None:
            return
        datagram = encode_frame(
            self.sealer,
            frame_type=frame_type,
            session_id=session.session_id,
            link_id=peer.link_id,
            counter=peer.next_counter(),
            seq=seq,
            payload=payload,
        )
        with contextlib.suppress(OSError):
            self._transport.sendto(datagram, peer.addr)
            peer.tx_packets += 1

    async def _tun_reader(self) -> None:
        """Internet -> client, spread back across the client's links."""

        loop = asyncio.get_running_loop()
        if self.device.fd >= 0:
            queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=4096)

            def _drain() -> None:
                for _ in range(64):
                    packet = self.device.read(self.device.mtu + 128)
                    if not packet:
                        return
                    with contextlib.suppress(asyncio.QueueFull):
                        queue.put_nowait(packet)

            loop.add_reader(self.device.fd, _drain)
            try:
                while not self._stop.is_set():
                    packet = await queue.get()
                    self._dispatch_downstream(packet)
            finally:
                with contextlib.suppress(Exception):
                    loop.remove_reader(self.device.fd)
        else:
            while not self._stop.is_set():
                packet = self.device.read()
                if packet is None:
                    await asyncio.sleep(0.01)
                    continue
                self._dispatch_downstream(packet)

    def _dispatch_downstream(self, packet: bytes) -> None:
        # A single client per tunnel subnet, so the newest live session wins.
        for session in sorted(self.sessions.values(), key=lambda s: s.created, reverse=True):
            peer = session.pick_return_link()
            if peer is None:
                continue
            self._send(session, peer, FrameType.DATA, seq=session.next_seq(), payload=packet)
            return

    async def _reorder_ticker(self) -> None:
        """Release packets whose predecessors never turned up.

        Without this, a gap left by a lost datagram would stall the flow until
        the next packet happened to arrive and drove the buffer forward.
        """

        interval = max(self.reorder_timeout_ms / 3.0, 5.0) / 1000.0
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            for session in list(self.sessions.values()):
                for packet in session.reorder.tick():
                    self.device.write(packet)

    async def _reaper(self) -> None:
        """Drop links and sessions that have gone silent."""

        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=30.0)
                return
            for session_id, session in list(self.sessions.items()):
                for link_id, peer in list(session.links.items()):
                    if not peer.alive:
                        log.info("session %08x: uplink %d timed out", session_id, link_id)
                        session.links.pop(link_id, None)
                if not session.links:
                    log.info("session %08x expired", session_id)
                    self.sessions.pop(session_id, None)

    def _note_rejection(self, addr: tuple[str, int]) -> None:
        """Say once, per source, that a datagram arrived but did not authenticate.

        Rejects are otherwise invisible: unauthenticated datagrams are dropped
        without a reply, so a client using the wrong key looks exactly like a
        client whose packets never arrive, and the usual next step is to go
        hunting through firewalls that were never the problem. One line naming
        the source separates the two.
        """

        if addr[0] in self._rejected_sources:
            return
        self._rejected_sources.add(addr[0])
        log.warning(
            "datagram from %s:%d failed to authenticate: it reached this server, "
            "so the port is open, but the pre-shared key does not match the one "
            "installed here. Check it with: sudo turbobond-server --pairing",
            *addr,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "listen": f"{self.host}:{self.port}",
            "device": self.device.snapshot(),
            "rejected": self._rejected,
            "sessions": [s.as_dict() for s in self.sessions.values()],
        }


class _ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: ConcentratorServer) -> None:
        self.server = server

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) <= MAX_DATAGRAM:
            self.server.handle_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        log.debug("concentrator socket error: %s", exc)


def _default_egress() -> str:
    """Interface holding the default route on the concentrator."""

    result = run(["ip", "route", "show", "default"], quiet=True, allow_missing=True)
    parts = result.stdout.split()
    if "dev" in parts:
        index = parts.index("dev")
        if index + 1 < len(parts):
            return parts[index + 1]
    return ""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="turbobond-server",
        description="Bonding concentrator: terminates turbobond client sessions and NATs them to the internet.",
    )
    parser.add_argument("--listen", default="0.0.0.0:5310", help="address:port to listen on")
    parser.add_argument("--psk", default=os.environ.get("TURBOBOND_PSK", ""), help="hex pre-shared key")
    parser.add_argument("--tun", default="tbond-srv", help="tunnel interface name")
    parser.add_argument("--mtu", type=int, default=1380, help="tunnel MTU")
    parser.add_argument("--local-cidr", default="10.77.0.1/30", help="server side tunnel address")
    parser.add_argument("--peer-ip", default="10.77.0.2", help="client side tunnel address")
    parser.add_argument("--egress", default="", help="egress interface (default: autodetect)")
    parser.add_argument("--reorder-ms", type=float, default=90.0, help="reorder hold time in milliseconds")
    parser.add_argument("--gen-psk", action="store_true", help="print a fresh pre-shared key and exit")
    parser.add_argument(
        "--provision",
        action="store_true",
        help="install the tuning and systemd service on this host, then print the pairing details",
    )
    parser.add_argument(
        "--public-ip",
        default="",
        help="address clients dial for --provision (default: autodetect)",
    )
    parser.add_argument(
        "--pairing",
        action="store_true",
        help="print the host, port and key this concentrator is already using",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="work out why clients cannot pair with this concentrator",
    )
    parser.add_argument("--log-level", default="INFO")
    return parser


def _provision(args: argparse.Namespace) -> int:
    """Stand the concentrator up on this host and say how to pair with it."""

    if not provision.is_root():
        print("error: --provision needs root.", file=sys.stderr)
        return 2

    # Re-running the installer must not unpair the clients that are already
    # configured, so an existing key is kept unless one is given explicitly.
    # An unreadable unit is not treated as an absent one: that would mint a new
    # key and silently unpair every client, where stopping is recoverable.
    try:
        existing = provision.installed_settings()
    except PermissionError:
        print(
            f"error: {provision.UNIT_PATH} exists but could not be read, so the key "
            "already in use cannot be preserved. Re-run as root, or pass --psk to "
            "set the key explicitly.",
            file=sys.stderr,
        )
        return 1
    psk = args.psk or (existing.psk if existing else "") or generate_psk()
    if existing and psk == existing.psk and not args.psk:
        print("  keeping the key already installed here")

    settings = provision.ConcentratorSettings(
        psk=psk,
        port=int(args.listen.rpartition(":")[2] or 5310),
        server_ip=args.local_cidr.split("/")[0],
        peer_ip=args.peer_ip,
        mtu=args.mtu,
        reorder_ms=args.reorder_ms,
    )

    for step in provision.provision_host(settings):
        print(f"  {step}")
    print(f"  {provision.open_firewall(settings.port)}")
    print(provision.pairing_summary(settings, args.public_ip or provision.detect_public_ip()))
    return 0


async def _serve(args: argparse.Namespace) -> int:
    host, _, port_text = args.listen.rpartition(":")
    server = ConcentratorServer(
        args.psk,
        host=host or "0.0.0.0",
        port=int(port_text or 5310),
        tun_name=args.tun,
        tunnel_mtu=args.mtu,
        local_cidr=args.local_cidr,
        peer_ip=args.peer_ip,
        egress_interface=args.egress,
        reorder_timeout_ms=args.reorder_ms,
    )
    await server.start()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    await server.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.log_level)

    if args.gen_psk:
        print(generate_psk())
        return 0
    if args.check:
        try:
            results, verdict = selfcheck.run_checks(args.public_ip)
        except PermissionError:
            print(
                "error: the concentrator's service file is readable only by root. "
                "Re-run this as: sudo turbobond-server --check",
                file=sys.stderr,
            )
            return 1
        print(selfcheck.format_report(results, verdict))
        return 1 if any(r.status == selfcheck.FAIL for r in results) else 0
    if args.pairing:
        try:
            settings = provision.installed_settings()
        except PermissionError:
            print(
                "error: the concentrator's service file is readable only by root, "
                "because it holds the key. Re-run this as: sudo turbobond-server --pairing",
                file=sys.stderr,
            )
            return 1
        if settings is None:
            print(
                "error: no installed concentrator found. Run the installer first.",
                file=sys.stderr,
            )
            return 1
        print(provision.pairing_summary(settings, args.public_ip or provision.detect_public_ip()))
        return 0
    if args.provision:
        return _provision(args)
    if not args.psk:
        print("error: --psk is required (or set TURBOBOND_PSK). Use --gen-psk to create one.", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_serve(args))
    except KeyboardInterrupt:  # pragma: no cover
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
