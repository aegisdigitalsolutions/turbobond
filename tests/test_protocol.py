from __future__ import annotations

import pytest

from turbobond.bond.protocol import (
    HEADER_LEN,
    MAX_PAYLOAD,
    FrameType,
    ReplayWindow,
    decode_frame,
    encode_frame,
    parse_header,
)
from turbobond.errors import BondError
from turbobond.util.crypto import Sealer, generate_psk


@pytest.fixture
def sealer() -> Sealer:
    return Sealer.from_psk(generate_psk())


def test_roundtrip_preserves_payload_and_metadata(sealer: Sealer) -> None:
    payload = b"\x45\x00" + b"packet body" * 10
    datagram = encode_frame(
        sealer,
        frame_type=FrameType.DATA,
        session_id=0xDEADBEEF,
        link_id=7,
        counter=42,
        seq=12345,
        payload=payload,
    )
    frame = decode_frame(sealer, datagram)

    assert frame is not None
    assert frame.type is FrameType.DATA
    assert frame.session_id == 0xDEADBEEF
    assert frame.link_id == 7
    assert frame.counter == 42
    assert frame.seq == 12345
    assert frame.payload == payload


def test_header_is_authenticated(sealer: Sealer) -> None:
    """Flipping a header byte must invalidate the whole datagram."""

    datagram = bytearray(
        encode_frame(
            sealer,
            frame_type=FrameType.DATA,
            session_id=1,
            link_id=1,
            counter=1,
            seq=1,
            payload=b"hello",
        )
    )
    # Byte 9 is inside the link id, which is part of the AEAD associated data.
    datagram[9] ^= 0xFF
    assert decode_frame(sealer, bytes(datagram)) is None


def test_ciphertext_tampering_is_rejected(sealer: Sealer) -> None:
    datagram = bytearray(
        encode_frame(sealer, frame_type=FrameType.DATA, session_id=1, link_id=1, counter=1, seq=1, payload=b"hello")
    )
    datagram[-1] ^= 0x01
    assert decode_frame(sealer, bytes(datagram)) is None


def test_a_different_key_cannot_open_the_frame(sealer: Sealer) -> None:
    datagram = encode_frame(
        sealer, frame_type=FrameType.DATA, session_id=1, link_id=1, counter=1, seq=1, payload=b"x"
    )
    assert decode_frame(Sealer.from_psk(generate_psk()), datagram) is None


def test_short_and_foreign_datagrams_are_ignored(sealer: Sealer) -> None:
    assert decode_frame(sealer, b"") is None
    assert decode_frame(sealer, b"\x00" * (HEADER_LEN - 1)) is None
    assert decode_frame(sealer, b"XX" + b"\x00" * 40) is None


def test_oversized_payload_is_refused(sealer: Sealer) -> None:
    with pytest.raises(BondError):
        encode_frame(
            sealer,
            frame_type=FrameType.DATA,
            session_id=1,
            link_id=1,
            counter=1,
            payload=b"\x00" * (MAX_PAYLOAD + 1),
        )


def test_parse_header_rejects_unknown_frame_type(sealer: Sealer) -> None:
    datagram = bytearray(
        encode_frame(sealer, frame_type=FrameType.DATA, session_id=1, link_id=1, counter=1, payload=b"x")
    )
    datagram[3] = 99
    with pytest.raises(BondError):
        parse_header(bytes(datagram))


def test_control_frames_carry_no_payload(sealer: Sealer) -> None:
    for frame_type in (FrameType.KEEPALIVE, FrameType.HANDSHAKE, FrameType.HANDSHAKE_ACK, FrameType.CLOSE):
        frame = decode_frame(
            sealer,
            encode_frame(sealer, frame_type=frame_type, session_id=2, link_id=3, counter=4),
        )
        assert frame is not None
        assert frame.type is frame_type
        assert frame.payload == b""
        assert not frame.is_data


class TestReplayWindow:
    def test_accepts_increasing_counters(self) -> None:
        window = ReplayWindow(size=64)
        assert all(window.check_and_update(n) for n in range(1, 50))

    def test_rejects_an_exact_replay(self) -> None:
        window = ReplayWindow(size=64)
        assert window.check_and_update(10)
        assert not window.check_and_update(10)

    def test_accepts_out_of_order_within_the_window(self) -> None:
        window = ReplayWindow(size=64)
        window.check_and_update(20)
        assert window.check_and_update(18)
        assert not window.check_and_update(18)

    def test_rejects_counters_older_than_the_window(self) -> None:
        window = ReplayWindow(size=16)
        window.check_and_update(1000)
        assert not window.check_and_update(900)

    def test_rejects_zero(self) -> None:
        assert not ReplayWindow().check_and_update(0)

    def test_large_jump_resets_the_bitmap(self) -> None:
        window = ReplayWindow(size=32)
        window.check_and_update(5)
        assert window.check_and_update(100_000)
        assert window.highest == 100_000
        assert not window.check_and_update(5)
