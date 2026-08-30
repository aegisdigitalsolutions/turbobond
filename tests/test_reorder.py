from __future__ import annotations

import random

from turbobond.bond.reorder import ReorderBuffer

# The buffer holds the first packets of a session for one reorder interval so it
# can learn the lowest sequence number in flight. Tests that want to be past
# that point push a priming packet and advance the clock beyond the deadline.
TIMEOUT_MS = 50.0
PRIMED = TIMEOUT_MS / 1000.0 + 0.001


def primed(timeout_ms: float = TIMEOUT_MS, capacity: int = 2048) -> tuple[ReorderBuffer, float]:
    """A buffer that has finished priming, plus the current clock value."""

    buffer = ReorderBuffer(timeout_ms=timeout_ms, capacity=capacity)
    buffer.push(1, b"prime", now=0.0)
    now = timeout_ms / 1000.0 + 0.001
    assert buffer.tick(now=now) == [b"prime"]
    return buffer, now


class TestPriming:
    def test_nothing_is_delivered_until_the_priming_window_closes(self) -> None:
        buffer = ReorderBuffer(timeout_ms=TIMEOUT_MS)
        assert buffer.push(1, b"a", now=0.0) == []
        assert buffer.tick(now=0.01) == []
        assert buffer.tick(now=PRIMED) == [b"a"]

    def test_a_session_that_opens_out_of_order_keeps_its_head(self) -> None:
        """If the slowest uplink carries packet 1, we must still deliver it."""

        buffer = ReorderBuffer(timeout_ms=TIMEOUT_MS)
        assert buffer.push(3, b"c", now=0.0) == []
        assert buffer.push(2, b"b", now=0.005) == []
        assert buffer.push(1, b"a", now=0.01) == []
        assert buffer.tick(now=PRIMED) == [b"a", b"b", b"c"]


class TestOrdering:
    def test_in_order_packets_pass_straight_through(self) -> None:
        buffer, now = primed()
        for seq in range(2, 21):
            assert buffer.push(seq, bytes([seq]), now=now) == [bytes([seq])]
        assert buffer.stats.reordered == 0

    def test_out_of_order_arrival_is_resequenced(self) -> None:
        """The whole point: links with different latency deliver out of order."""

        buffer, now = primed()
        assert buffer.push(2, b"b", now=now) == [b"b"]
        # 4 arrives before 3, so it must be held.
        assert buffer.push(4, b"d", now=now) == []
        # 3 arrives and unblocks both.
        assert buffer.push(3, b"c", now=now + 0.005) == [b"c", b"d"]
        assert buffer.stats.reordered == 1

    def test_shuffled_burst_is_fully_restored(self) -> None:
        """Reordering across links is bounded by their latency difference.

        Packets are shuffled within sliding windows rather than globally,
        because that is what a real bond produces: a packet arrives early or
        late by roughly the spread between the fastest and slowest uplink.
        """

        buffer = ReorderBuffer(timeout_ms=1000, capacity=512)
        payloads = [bytes([i % 256]) + i.to_bytes(2, "big") for i in range(1, 201)]
        rng = random.Random(1234)
        order: list[int] = []
        for start in range(1, 201, 8):
            window = list(range(start, min(start + 8, 201)))
            rng.shuffle(window)
            order.extend(window)

        delivered: list[bytes] = []
        for seq in order:
            delivered.extend(buffer.push(seq, payloads[seq - 1], now=0.0))
        delivered.extend(buffer.flush())

        assert delivered == payloads

    def test_first_sequence_number_does_not_have_to_be_one(self) -> None:
        buffer = ReorderBuffer(timeout_ms=TIMEOUT_MS)
        buffer.push(9000, b"x", now=0.0)
        assert buffer.tick(now=PRIMED) == [b"x"]
        assert buffer.push(9001, b"y", now=PRIMED) == [b"y"]


class TestGapHandling:
    def test_a_lost_packet_releases_the_queue_after_the_deadline(self) -> None:
        buffer, now = primed()
        assert buffer.push(3, b"c", now=now) == []
        # Packet 2 never shows up; at the deadline we stop waiting for it.
        assert buffer.push(4, b"d", now=now + 0.15) == [b"c", b"d"]
        assert buffer.stats.gap_skips >= 1

    def test_tick_releases_a_stranded_tail(self) -> None:
        """Without a timer, a stream that stops mid-gap would strand its tail."""

        buffer, now = primed()
        assert buffer.push(5, b"e", now=now) == []
        assert buffer.tick(now=now + 0.01) == []
        assert buffer.tick(now=now + 0.2) == [b"e"]

    def test_gap_wait_is_bounded_by_the_timeout(self) -> None:
        buffer, now = primed(timeout_ms=30.0)
        buffer.push(10, b"j", now=now)
        assert buffer.tick(now=now + 0.029) == []
        assert buffer.tick(now=now + 0.031) == [b"j"]

    def test_a_gap_that_fills_in_time_is_not_skipped(self) -> None:
        buffer, now = primed()
        assert buffer.push(4, b"d", now=now) == []
        assert buffer.push(3, b"c", now=now + 0.001) == []
        assert buffer.push(2, b"b", now=now + 0.002) == [b"b", b"c", b"d"]
        assert buffer.stats.gap_skips == 0


class TestDuplicatesAndLateness:
    def test_duplicates_are_dropped(self) -> None:
        """Redundant transmission of SIP relies on this."""

        buffer, now = primed()
        assert buffer.push(2, b"b", now=now) == [b"b"]
        assert buffer.push(2, b"b", now=now) == []
        assert buffer.stats.duplicates == 1

    def test_duplicate_of_a_still_pending_packet_is_dropped(self) -> None:
        buffer, now = primed()
        buffer.push(3, b"c", now=now)
        assert buffer.push(3, b"c", now=now) == []
        assert buffer.stats.duplicates == 1

    def test_packets_arriving_after_their_slot_was_skipped_are_discarded(self) -> None:
        buffer, now = primed()
        buffer.push(4, b"d", now=now)
        # The gap at 2 and 3 times out and 4 is released without them.
        assert buffer.tick(now=now + 0.2) == [b"d"]
        assert buffer.push(2, b"b", now=now + 0.3) == []
        assert buffer.stats.late_drops == 1


class TestCapacity:
    def test_overflow_flushes_rather_than_growing_without_bound(self) -> None:
        buffer = ReorderBuffer(timeout_ms=10_000, capacity=32)
        buffer.push(1, b"start", now=0.0)
        released: list[bytes] = []
        # Feed a long run with a permanent hole at sequence 2.
        for seq in range(3, 90):
            released.extend(buffer.push(seq, bytes([seq % 256]), now=0.0))
        assert buffer.stats.overflow_flushes >= 1
        assert buffer.pending <= 33
        assert released

    def test_flush_drains_everything_in_order(self) -> None:
        buffer, now = primed(timeout_ms=10_000.0)
        buffer.push(4, b"d", now=now)
        buffer.push(3, b"c", now=now)
        assert buffer.flush() == [b"c", b"d"]
        assert buffer.pending == 0

    def test_reset_clears_all_state(self) -> None:
        buffer, now = primed()
        buffer.push(5, b"e", now=now)
        buffer.reset()
        assert buffer.pending == 0
        assert buffer.next_seq == 0
        buffer.push(100, b"z", now=0.0)
        assert buffer.tick(now=PRIMED) == [b"z"]


def test_snapshot_reports_useful_counters() -> None:
    buffer, _ = primed(timeout_ms=75.0, capacity=128)
    snapshot = buffer.snapshot()
    assert snapshot["timeout_ms"] == 75.0
    assert snapshot["capacity"] == 128
    assert snapshot["stats"]["delivered"] == 1
