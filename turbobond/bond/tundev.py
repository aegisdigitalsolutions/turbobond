"""Creation and lifecycle of the bonded TUN interface.

The tunnel is a layer-3 device: the kernel routes IP packets into ``tbond0``,
we read them, spread them over the uplinks, and the concentrator writes them out
the other side. In dry-run mode a loopback-backed stub stands in for the real
device so the whole datapath can be exercised without CAP_NET_ADMIN.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import struct
from typing import Any

from turbobond.errors import DependencyError, PrivilegeError
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run

log = get_logger("bond.tundev")

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUN_CLONE_DEVICE = "/dev/net/tun"


class TunDevice:
    """A layer-3 TUN interface."""

    def __init__(self, name: str = "tbond0", *, mtu: int = 1380) -> None:
        self.name = name
        self.mtu = mtu
        self._fd: int | None = None
        self._simulated = False
        self._sim_queue: list[bytes] = []

    # ------------------------------------------------------------------- open

    def open(self) -> None:
        """Create/attach the device and put it in non-blocking mode."""

        if self._fd is not None:
            return

        if is_dry_run():
            self._simulated = True
            log.info("[dry-run] simulated TUN device %s (mtu %d)", self.name, self.mtu)
            return

        if not os.path.exists(TUN_CLONE_DEVICE):
            raise DependencyError(
                f"{TUN_CLONE_DEVICE} is missing, so a bonded tunnel cannot be created",
                remedy="Load the tun module ('modprobe tun') or run turbobond on a host with TUN support.",
            )

        try:
            fd = os.open(TUN_CLONE_DEVICE, os.O_RDWR)
        except PermissionError as exc:
            raise PrivilegeError(
                f"cannot open {TUN_CLONE_DEVICE}",
                remedy="turbobond must run as root or hold CAP_NET_ADMIN to create the bonded interface.",
            ) from exc

        try:
            ifr = struct.pack("16sH", self.name.encode()[:15], IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(fd, TUNSETIFF, ifr)
        except OSError as exc:
            os.close(fd)
            raise PrivilegeError(
                f"could not create TUN interface {self.name}: {exc}",
                remedy="Check that the name is free ('ip link show') and that the process has CAP_NET_ADMIN.",
            ) from exc

        os.set_blocking(fd, False)
        self._fd = fd
        log.info("TUN interface %s created", self.name)

    # ------------------------------------------------------------- addressing

    def configure(self, local_cidr: str, peer_ip: str) -> None:
        """Bring the interface up with its point-to-point addressing."""

        run(["ip", "link", "set", "dev", self.name, "mtu", str(self.mtu)], allow_missing=True)
        run(["ip", "addr", "flush", "dev", self.name], quiet=True, allow_missing=True)
        run(["ip", "addr", "add", local_cidr, "peer", peer_ip, "dev", self.name], allow_missing=True)
        run(["ip", "link", "set", "dev", self.name, "up"], allow_missing=True)
        # A deep queue on a bonded device just adds latency; the scheduler paces.
        run(["ip", "link", "set", "dev", self.name, "txqueuelen", "1000"], quiet=True, allow_missing=True)
        log.info("interface %s configured: %s peer %s mtu %d", self.name, local_cidr, peer_ip, self.mtu)

    # --------------------------------------------------------------------- io

    @property
    def fd(self) -> int:
        if self._simulated:
            return -1
        if self._fd is None:
            raise DependencyError("TUN device is not open")
        return self._fd

    @property
    def is_open(self) -> bool:
        return self._fd is not None or self._simulated

    def read(self, size: int = 2048) -> bytes | None:
        """Read one packet. Returns ``None`` when nothing is queued."""

        if self._simulated:
            return self._sim_queue.pop(0) if self._sim_queue else None
        if self._fd is None:
            return None
        try:
            return os.read(self._fd, size)
        except BlockingIOError:
            return None
        except OSError as exc:
            log.debug("TUN read failed: %s", exc)
            return None

    def write(self, packet: bytes) -> int:
        """Inject a packet into the kernel."""

        if self._simulated:
            self._sim_queue.append(packet)
            return len(packet)
        if self._fd is None:
            return 0
        try:
            return os.write(self._fd, packet)
        except BlockingIOError:
            return 0
        except OSError as exc:
            log.debug("TUN write failed: %s", exc)
            return 0

    def inject_for_test(self, packet: bytes) -> None:
        """Queue a packet as if the kernel had sent it. Simulation only."""

        if not self._simulated:
            raise DependencyError("inject_for_test is only available on a simulated device")
        self._sim_queue.append(packet)

    # ------------------------------------------------------------------ close

    def close(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
        self._simulated = False
        self._sim_queue.clear()

    def teardown(self) -> None:
        """Remove the interface entirely."""

        self.close()
        run(["ip", "link", "set", "dev", self.name, "down"], quiet=True, allow_missing=True)
        run(["ip", "link", "delete", "dev", self.name], quiet=True, allow_missing=True)

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mtu": self.mtu,
            "open": self.is_open,
            "simulated": self._simulated,
        }
