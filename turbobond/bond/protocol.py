"""Wire format for the bonding tunnel.

Every datagram sent over an uplink looks like::

    +--------+--------+--------+--------+
    | magic (2) | ver(1) | type(1)      |
    +--------+--------+--------+--------+
    | session id (4)                    |
    +-----------------------------------+
    | link id (4)                       |
    +-----------------------------------+
    | counter (8)  - AEAD nonce input   |
    +-----------------------------------+
    | ciphertext (AEAD sealed payload)  |
    +-----------------------------------+

The header is authenticated as additional data, so a middlebox cannot rewrite
the link id or session id without the peer noticing. Inside the ciphertext a
DATA frame carries an 8-byte global sequence number followed by the original IP
packet, which is what the receiver's reorder buffer keys on.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from turbobond.errors import BondError
from turbobond.version import PROTOCOL_VERSION

MAGIC = b"TB"
HEADER_FMT = "!2sBBIIQ"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 20 bytes
SEQ_LEN = 8
# ChaCha20-Poly1305 tag.
TAG_LEN = 16
# Largest inner IP packet we will ever carry.
MAX_PAYLOAD = 1600
MAX_DATAGRAM = HEADER_LEN + SEQ_LEN + MAX_PAYLOAD + TAG_LEN


class FrameType(IntEnum):
    DATA = 1
    KEEPALIVE = 2
    HANDSHAKE = 3
    HANDSHAKE_ACK = 4
    LINK_STATS = 5
    CLOSE = 6


@dataclass(slots=True)
class Frame:
    """A decoded tunnel datagram."""

    type: FrameType
    session_id: int
    link_id: int
    counter: int
    seq: int = 0
    payload: bytes = b""
    version: int = PROTOCOL_VERSION

    @property
    def is_data(self) -> bool:
        return self.type is FrameType.DATA


def pack_header(frame_type: FrameType, session_id: int, link_id: int, counter: int) -> bytes:
    return struct.pack(
        HEADER_FMT,
        MAGIC,
        PROTOCOL_VERSION,
        int(frame_type),
        session_id & 0xFFFFFFFF,
        link_id & 0xFFFFFFFF,
        counter & 0xFFFFFFFFFFFFFFFF,
    )


def parse_header(data: bytes) -> tuple[FrameType, int, int, int, int]:
    """Return ``(type, session_id, link_id, counter, version)``."""

    if len(data) < HEADER_LEN:
        raise BondError(f"datagram too short: {len(data)} < {HEADER_LEN}")
    magic, version, raw_type, session_id, link_id, counter = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    if magic != MAGIC:
        raise BondError("bad magic; not a turbobond datagram")
    if version != PROTOCOL_VERSION:
        raise BondError(f"unsupported protocol version {version} (expected {PROTOCOL_VERSION})")
    try:
        frame_type = FrameType(raw_type)
    except ValueError as exc:
        raise BondError(f"unknown frame type {raw_type}") from exc
    return frame_type, session_id, link_id, counter, version


def encode_frame(
    sealer,
    *,
    frame_type: FrameType,
    session_id: int,
    link_id: int,
    counter: int,
    seq: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build a sealed datagram ready to put on the wire."""

    if len(payload) > MAX_PAYLOAD:
        raise BondError(f"payload of {len(payload)} bytes exceeds the {MAX_PAYLOAD} byte limit")
    header = pack_header(frame_type, session_id, link_id, counter)
    plaintext = struct.pack("!Q", seq & 0xFFFFFFFFFFFFFFFF) + payload
    ciphertext = sealer.seal(plaintext, link_id=link_id, counter=counter, aad=header)
    return header + ciphertext


def decode_frame(sealer, data: bytes) -> Frame | None:
    """Parse and authenticate a datagram. Returns ``None`` if it is not genuine."""

    try:
        frame_type, session_id, link_id, counter, version = parse_header(data)
    except BondError:
        return None
    header = data[:HEADER_LEN]
    ciphertext = data[HEADER_LEN:]
    if len(ciphertext) < SEQ_LEN + TAG_LEN:
        return None
    plaintext = sealer.open(ciphertext, link_id=link_id, counter=counter, aad=header)
    if plaintext is None or len(plaintext) < SEQ_LEN:
        return None
    (seq,) = struct.unpack("!Q", plaintext[:SEQ_LEN])
    return Frame(
        type=frame_type,
        session_id=session_id,
        link_id=link_id,
        counter=counter,
        seq=seq,
        payload=plaintext[SEQ_LEN:],
        version=version,
    )


class ReplayWindow:
    """Sliding window that rejects replayed or badly stale counters.

    One window is kept per link, since counters are per-link monotonic.
    """

    __slots__ = ("_bitmap", "_highest", "_size")

    def __init__(self, size: int = 4096) -> None:
        self._size = size
        self._highest = 0
        self._bitmap = 0

    def check_and_update(self, counter: int) -> bool:
        """Return True if ``counter`` is fresh; records it as seen."""

        if counter == 0:
            return False
        if counter > self._highest:
            shift = counter - self._highest
            if shift >= self._size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self._size) - 1)
            self._highest = counter
            return True

        offset = self._highest - counter
        if offset >= self._size:
            return False
        mask = 1 << offset
        if self._bitmap & mask:
            return False
        self._bitmap |= mask
        return True

    @property
    def highest(self) -> int:
        return self._highest
