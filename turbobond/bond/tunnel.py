"""Client half of the bonding tunnel.

One UDP socket is bound per uplink (via ``SO_BINDTODEVICE``) so the kernel is
forced to send that socket's datagrams out that specific interface regardless of
the routing table. Packets read from the TUN device are sealed, stamped with a
bond-wide sequence number, handed to the scheduler, and written to the chosen
socket(s). Datagrams arriving on any socket are authenticated, resequenced and
written back into the TUN device.

That is what makes this real aggregation rather than per-flow balancing: a
single TCP connection's packets are spread across every uplink, so one download
can exceed the capacity of any individual link.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from turbobond.bond.protocol import (
    HEADER_LEN,
    MAX_DATAGRAM,
    FrameType,
    ReplayWindow,
    decode_frame,
    encode_frame,
)
from turbobond.bond.reorder import ReorderBuffer
from turbobond.bond.scheduler import BondScheduler, SchedulerMode, is_critical_packet
from turbobond.bond.tundev import TUN_CLONE_DEVICE, TunDevice
from turbobond.config import ConcentratorConfig, SipConfig
from turbobond.errors import BondError
from turbobond.links.model import Link
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run
from turbobond.util.crypto import Sealer

log = get_logger("bond.tunnel")

HANDSHAKE_TIMEOUT_S = 6.0
HANDSHAKE_RETRIES = 3


@dataclass
class LinkSocket:
    """The UDP socket dedicated to one uplink."""

    link: Link
    sock: socket.socket
    counter: int = 0
    tx_packets: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    last_rx_ts: float = 0.0
    last_tx_ts: float = 0.0
    handshaken: bool = False
    replay: ReplayWindow = field(default_factory=ReplayWindow)

    def next_counter(self) -> int:
        self.counter += 1
        return self.counter

    def as_dict(self) -> dict[str, Any]:
        return {
            "link": self.link.name,
            "interface": self.link.interface,
            "link_id": self.link.link_id,
            "handshaken": self.handshaken,
            "tx_packets": self.tx_packets,
            "tx_bytes": self.tx_bytes,
            "rx_packets": self.rx_packets,
            "rx_bytes": self.rx_bytes,
            "last_rx_age_s": round(time.time() - self.last_rx_ts, 1) if self.last_rx_ts else None,
        }


class BondingTunnel:
    """Aggregates several uplinks into one logical interface."""

    def __init__(
        self,
        cfg: ConcentratorConfig,
        links: list[Link],
        *,
        sip: SipConfig | None = None,
        mode: SchedulerMode = SchedulerMode.WEIGHTED,
    ) -> None:
        self.cfg = cfg
        self.links = links
        self.sip = sip
        self.sealer = Sealer.from_psk(cfg.ensure_psk())
        self.session_id = int.from_bytes(secrets.token_bytes(4), "big") or 1
        self.device = TunDevice(cfg.tun_device, mtu=cfg.tunnel_mtu)
        self.scheduler = BondScheduler(links, mode=mode)
        self.reorder = ReorderBuffer(timeout_ms=cfg.reorder_timeout_ms, capacity=cfg.reorder_capacity)
        self.sockets: dict[int, LinkSocket] = {}
        self._seq = 0
        self._tasks: list[asyncio.Task[None]] = []
        self._stop = asyncio.Event()
        self._running = False
        self._started_ts = 0.0
        self._sip_ports: set[int] = set(sip.signalling_ports) | set(sip.tls_ports) if sip else set()
        self._dropped_no_link = 0
        self._rx_rejected = 0

    # --------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return self._running

    @property
    def peer(self) -> tuple[str, int]:
        return (self.cfg.host, self.cfg.port)

    async def start(self) -> None:
        """Open the device, bind a socket per uplink, and start the datapath."""

        if self._running:
            return
        if not self.cfg.enabled:
            raise BondError(
                "bonding tunnel is disabled",
                remedy="Set concentrator.enabled and concentrator.host, or run in local-aggregation mode.",
            )

        self.device.open()
        self.device.configure(self.cfg.tunnel_ip_local, self.cfg.tunnel_ip_remote)

        bound = 0
        for link in self.links:
            if not link.enabled:
                continue
            try:
                self.sockets[link.link_id] = self._bind_link(link)
                bound += 1
            except OSError as exc:
                log.warning("could not bind a tunnel socket on %s: %s", link.interface, exc)
                link.tunnel_ready = False

        if bound == 0:
            self.device.teardown()
            raise BondError(
                "no uplink could be bound for the bonding tunnel",
                remedy="Check that at least one WAN interface is up and that turbobond has CAP_NET_RAW.",
            )

        await self._handshake_all()

        self._stop.clear()
        self._running = True
        self._started_ts = time.time()
        self._tasks = [
            asyncio.create_task(self._tun_reader(), name="tbond-tun-reader"),
            asyncio.create_task(self._socket_reader(), name="tbond-sock-reader"),
            asyncio.create_task(self._keepalive_loop(), name="tbond-keepalive"),
            asyncio.create_task(self._reorder_ticker(), name="tbond-reorder-tick"),
        ]
        log.info(
            "bonding tunnel up: %d uplink(s) -> %s:%d, session %08x",
            bound,
            self.cfg.host,
            self.cfg.port,
            self.session_id,
        )

    def _bind_link(self, link: Link) -> LinkSocket:
        """Create a UDP socket nailed to a single interface."""

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Large buffers: a bonded pipe bursts harder than any single link.
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

        if not is_dry_run():
            if hasattr(socket, "SO_BINDTODEVICE"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, link.interface.encode())
                except OSError as exc:
                    # Without CAP_NET_RAW we fall back to source-address binding,
                    # which still pins the path as long as policy routing is up.
                    log.debug("SO_BINDTODEVICE unavailable on %s (%s); binding by source IP", link.interface, exc)
                    if link.source_ip:
                        sock.bind((link.source_ip, 0))
            elif link.source_ip:
                sock.bind((link.source_ip, 0))
            # Never fragment: the tunnel MTU is chosen to fit inside every path.
            with contextlib.suppress(OSError, AttributeError):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, 2)  # IP_PMTUDISC_DO
            # Mark media/tunnel traffic as low-latency for any DSCP-aware hop.
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0xB8)  # DSCP EF
        else:
            sock.bind(("127.0.0.1", 0))

        sock.setblocking(False)
        link.tunnel_ready = True
        return LinkSocket(link=link, sock=sock)

    async def stop(self) -> None:
        self._stop.set()
        self._running = False
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()

        for link_socket in self.sockets.values():
            with contextlib.suppress(OSError):
                await self._send_control(link_socket, FrameType.CLOSE)
            with contextlib.suppress(OSError):
                link_socket.sock.close()
            link_socket.link.tunnel_ready = False
        self.sockets.clear()
        self.device.teardown()
        log.info("bonding tunnel stopped")

    # --------------------------------------------------------------- handshake

    async def _handshake_all(self) -> None:
        """Announce every link to the concentrator so it learns their addresses."""

        results = await asyncio.gather(
            *(self._handshake_link(ls) for ls in self.sockets.values()),
            return_exceptions=True,
        )
        ok = sum(1 for r in results if r is True)
        if ok == 0 and not is_dry_run():
            # The concentrator may be slow to answer; the datapath keeps retrying
            # via keepalives, so this is a warning rather than a hard failure.
            log.warning("no uplink completed the handshake yet; keepalives will keep retrying")
        else:
            log.info("%d/%d uplink(s) handshaken with the concentrator", ok, len(self.sockets))

    async def _handshake_link(self, link_socket: LinkSocket) -> bool:
        if is_dry_run():
            link_socket.handshaken = True
            return True
        loop = asyncio.get_running_loop()
        for _ in range(HANDSHAKE_RETRIES):
            await self._send_control(link_socket, FrameType.HANDSHAKE)
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(link_socket.sock, MAX_DATAGRAM),
                    timeout=HANDSHAKE_TIMEOUT_S / HANDSHAKE_RETRIES,
                )
            except (TimeoutError, OSError):
                continue
            frame = decode_frame(self.sealer, data)
            if frame is not None and frame.type in (FrameType.HANDSHAKE_ACK, FrameType.KEEPALIVE):
                link_socket.handshaken = True
                link_socket.last_rx_ts = time.time()
                log.info("uplink %s handshaken", link_socket.link.name)
                return True
        return False

    # ---------------------------------------------------------------- datapath

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    async def _tun_reader(self) -> None:
        """Kernel -> uplinks."""

        loop = asyncio.get_running_loop()
        if self.device.fd >= 0:
            queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=4096)
            loop.add_reader(self.device.fd, self._drain_tun_into, queue)
            try:
                while not self._stop.is_set():
                    packet = await queue.get()
                    await self._send_packet(packet)
            finally:
                with contextlib.suppress(Exception):
                    loop.remove_reader(self.device.fd)
        else:
            # Simulated device: poll the in-memory queue.
            while not self._stop.is_set():
                packet = self.device.read()
                if packet is None:
                    await asyncio.sleep(0.01)
                    continue
                await self._send_packet(packet)

    def _drain_tun_into(self, queue: asyncio.Queue[bytes]) -> None:
        """Readiness callback: pull every queued packet out of the device."""

        for _ in range(64):
            packet = self.device.read(self.cfg.tunnel_mtu + 128)
            if not packet:
                return
            try:
                queue.put_nowait(packet)
            except asyncio.QueueFull:
                # Better to drop here than to build an unbounded latency queue.
                self._dropped_no_link += 1
                return

    async def _send_packet(self, packet: bytes) -> None:
        critical = bool(self.cfg.duplicate_critical and self._sip_ports and is_critical_packet(packet, self._sip_ports))
        chosen = self.scheduler.select(len(packet), critical=critical)
        if not chosen:
            self._dropped_no_link += 1
            return

        seq = self._next_seq()
        for link in chosen:
            link_socket = self.sockets.get(link.link_id)
            if link_socket is None:
                continue
            datagram = encode_frame(
                self.sealer,
                frame_type=FrameType.DATA,
                session_id=self.session_id,
                link_id=link.link_id,
                counter=link_socket.next_counter(),
                seq=seq,
                payload=packet,
            )
            await self._sendto(link_socket, datagram)

    async def _sendto(self, link_socket: LinkSocket, datagram: bytes) -> None:
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(link_socket.sock, datagram, self.peer)
        except (OSError, AttributeError) as exc:
            # Network unreachable on one link must not stall the others.
            log.debug("send on %s failed: %s", link_socket.link.name, exc)
            return
        link_socket.tx_packets += 1
        link_socket.tx_bytes += len(datagram)
        link_socket.last_tx_ts = time.time()

    async def _socket_reader(self) -> None:
        """Uplinks -> kernel."""

        await asyncio.gather(
            *(self._read_socket(ls) for ls in list(self.sockets.values())),
            return_exceptions=True,
        )

    async def _read_socket(self, link_socket: LinkSocket) -> None:
        loop = asyncio.get_running_loop()
        while not self._stop.is_set():
            try:
                data = await loop.sock_recv(link_socket.sock, MAX_DATAGRAM)
            except (OSError, asyncio.CancelledError):
                if self._stop.is_set():
                    return
                await asyncio.sleep(0.05)
                continue
            if not data or len(data) < HEADER_LEN:
                continue
            self._handle_datagram(link_socket, data)

    def _handle_datagram(self, link_socket: LinkSocket, data: bytes) -> None:
        frame = decode_frame(self.sealer, data)
        if frame is None:
            self._rx_rejected += 1
            return
        if not link_socket.replay.check_and_update(frame.counter):
            self._rx_rejected += 1
            return

        link_socket.rx_packets += 1
        link_socket.rx_bytes += len(data)
        link_socket.last_rx_ts = time.time()
        link_socket.handshaken = True

        if frame.type is FrameType.DATA and frame.payload:
            for packet in self.reorder.push(frame.seq, frame.payload):
                self.device.write(packet)
        elif frame.type is FrameType.CLOSE:
            log.warning("concentrator closed the session on %s", link_socket.link.name)
            link_socket.handshaken = False

    # -------------------------------------------------------------- background

    async def _send_control(self, link_socket: LinkSocket, frame_type: FrameType) -> None:
        datagram = encode_frame(
            self.sealer,
            frame_type=frame_type,
            session_id=self.session_id,
            link_id=link_socket.link.link_id,
            counter=link_socket.next_counter(),
            seq=0,
            payload=b"",
        )
        await self._sendto(link_socket, datagram)

    async def _keepalive_loop(self) -> None:
        """Holds NAT bindings open and re-handshakes links that fell out."""

        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self.cfg.keepalive_s)
                return
            now = time.time()
            for link_socket in list(self.sockets.values()):
                if not link_socket.link.enabled:
                    continue
                with contextlib.suppress(Exception):
                    await self._send_control(link_socket, FrameType.KEEPALIVE)
                stale = link_socket.last_rx_ts and (now - link_socket.last_rx_ts) > self.cfg.keepalive_s * 6
                if stale and link_socket.handshaken:
                    log.warning("uplink %s went quiet; re-handshaking", link_socket.link.name)
                    link_socket.handshaken = False
                    with contextlib.suppress(Exception):
                        await self._handshake_link(link_socket)

    async def _reorder_ticker(self) -> None:
        """Releases packets stuck behind a gap when the stream pauses."""

        interval = max(0.005, self.cfg.reorder_timeout_ms / 2000.0)
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
                return
            for packet in self.reorder.tick():
                self.device.write(packet)

    # ------------------------------------------------------------------- views

    def refresh_links(self, links: list[Link]) -> None:
        """Update the bond membership after a link state change."""

        self.links = links
        self.scheduler.set_links(links)
        for link in links:
            link.tunnel_ready = link.link_id in self.sockets and self.sockets[link.link_id].handshaken

    def snapshot(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "session_id": f"{self.session_id:08x}",
            "peer": f"{self.cfg.host}:{self.cfg.port}",
            "device": self.device.snapshot(),
            "uptime_s": round(time.time() - self._started_ts, 1) if self._started_ts else 0,
            "sequence": self._seq,
            "dropped_no_link": self._dropped_no_link,
            "rx_rejected": self._rx_rejected,
            "sockets": [ls.as_dict() for ls in self.sockets.values()],
            "scheduler": self.scheduler.snapshot(),
            "reorder": self.reorder.snapshot(),
        }


def tunnel_supported() -> tuple[bool, str]:
    """Whether this host can create the bonded interface at all."""

    if is_dry_run():
        return True, "dry-run"
    if not os.path.exists(TUN_CLONE_DEVICE):
        return False, f"{TUN_CLONE_DEVICE} is missing (the tun kernel module is not loaded)"
    if os.geteuid() != 0:
        return False, "turbobond is not running as root, so it cannot create a TUN interface"
    return True, "ok"
