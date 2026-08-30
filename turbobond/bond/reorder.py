"""Receive-side resequencing for the bonded stream.

Spreading one flow over links with different latencies means packets arrive out
of order, and TCP reads that as congestion. The reorder buffer holds early
arrivals briefly so the far side sees the original ordering, while a deadline
guarantees a genuinely lost packet never stalls the pipe for more than
``timeout_ms``.

It also drops duplicates, which is what makes redundant transmission of SIP
signalling safe.
"""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass
from typing import Any

from turbobond.logging_setup import get_logger

log = get_logger("bond.reorder")


@dataclass(slots=True)
class ReorderStats:
    delivered: int = 0
    reordered: int = 0
    duplicates: int = 0
    late_drops: int = 0
    gap_skips: int = 0
    overflow_flushes: int = 0
    max_held: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "delivered": self.delivered,
            "reordered": self.reordered,
            "duplicates": self.duplicates,
            "late_drops": self.late_drops,
            "gap_skips": self.gap_skips,
            "overflow_flushes": self.overflow_flushes,
            "max_held": self.max_held,
        }


class ReorderBuffer:
    """Restores sequence order across links with differing latency.

    Sequence numbers are assigned by the sender across the whole bond, so the
    receiver can tell "arrived early" from "was lost".
    """

    def __init__(self, *, timeout_ms: float = 90.0, capacity: int = 2048) -> None:
        self.timeout_s = max(0.0, timeout_ms / 1000.0)
        self.capacity = max(8, capacity)
        self.stats = ReorderStats()
        # Min-heap of pending sequence numbers, plus the payload/deadline map.
        self._heap: list[int] = []
        self._pending: dict[int, tuple[bytes, float]] = {}
        self._seen: set[int] = set()
        self._next_seq = 0
        self._started = False
        # A session can open out of order, so nothing is delivered until one
        # reorder interval has passed and we know the lowest sequence number in
        # flight. Without this the very first packets would be lost whenever the
        # slowest uplink happened to carry the head of the stream.
        self._priming = False
        self._prime_deadline = 0.0

    # ------------------------------------------------------------------ input

    def push(self, seq: int, payload: bytes, *, now: float | None = None) -> list[bytes]:
        """Accept a packet and return everything that is now deliverable, in order."""

        now = time.monotonic() if now is None else now

        if not self._started:
            self._started = True
            self._next_seq = seq
            self._priming = True
            self._prime_deadline = now + self.timeout_s
        elif self._priming and seq < self._next_seq:
            # Still learning where the stream starts; rewind to the earliest.
            self._next_seq = seq

        if seq in self._pending or seq in self._seen:
            # A second copy of something we already have. Redundant transmission
            # of SIP signalling relies on these being dropped silently.
            self.stats.duplicates += 1
            return []
        if seq < self._next_seq:
            # So late that its slot has already been skipped past.
            self.stats.late_drops += 1
            return []

        self._pending[seq] = (payload, now + self.timeout_s)
        heapq.heappush(self._heap, seq)
        self.stats.max_held = max(self.stats.max_held, len(self._pending))
        if seq != self._next_seq:
            self.stats.reordered += 1

        released = self._drain(now)
        if len(self._pending) > self.capacity:
            released.extend(self._force_flush(now))
        return released

    # ----------------------------------------------------------------- output

    def _drain(self, now: float) -> list[bytes]:
        """Release every packet that is in order, or whose deadline has passed."""

        if self._priming:
            if now < self._prime_deadline:
                return []
            self._priming = False

        out: list[bytes] = []
        while self._heap:
            head = self._heap[0]
            if head < self._next_seq:
                heapq.heappop(self._heap)
                self._pending.pop(head, None)
                continue

            if head == self._next_seq:
                heapq.heappop(self._heap)
                payload, _ = self._pending.pop(head)
                out.append(payload)
                self._advance(head)
                continue

            # There is a gap. Wait for the missing packet until its deadline.
            _, deadline = self._pending[head]
            if now >= deadline:
                skipped = head - self._next_seq
                self.stats.gap_skips += skipped
                heapq.heappop(self._heap)
                payload, _ = self._pending.pop(head)
                out.append(payload)
                self._advance(head)
                continue
            break
        return out

    def _force_flush(self, now: float) -> list[bytes]:
        """Buffer is over capacity: release the oldest half immediately."""

        self._priming = False
        self.stats.overflow_flushes += 1
        target = len(self._pending) - (self.capacity // 2)
        out: list[bytes] = []
        while self._heap and target > 0:
            head = heapq.heappop(self._heap)
            entry = self._pending.pop(head, None)
            target -= 1
            if entry is None:
                continue
            if head < self._next_seq:
                continue
            out.append(entry[0])
            self._advance(head)
        return out

    def _advance(self, delivered_seq: int) -> None:
        self.stats.delivered += 1
        self._next_seq = delivered_seq + 1
        self._seen.add(delivered_seq)
        if len(self._seen) > self.capacity * 4:
            cutoff = self._next_seq - self.capacity * 2
            self._seen = {s for s in self._seen if s >= cutoff}

    def tick(self, *, now: float | None = None) -> list[bytes]:
        """Release anything whose deadline expired while no packets arrived.

        Call this on a timer; without it a stream that stops mid-gap would leave
        the buffered tail stranded.
        """

        return self._drain(time.monotonic() if now is None else now)

    def flush(self) -> list[bytes]:
        """Release everything held, in sequence order. Used on shutdown."""

        self._priming = False
        out: list[bytes] = []
        while self._heap:
            head = heapq.heappop(self._heap)
            entry = self._pending.pop(head, None)
            if entry is not None and head >= self._next_seq:
                out.append(entry[0])
                self._advance(head)
        return out

    # ------------------------------------------------------------------ views

    @property
    def pending(self) -> int:
        return len(self._pending)

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def reset(self) -> None:
        self._heap.clear()
        self._pending.clear()
        self._seen.clear()
        self._next_seq = 0
        self._started = False
        self._priming = False
        self._prime_deadline = 0.0

    def snapshot(self) -> dict[str, Any]:
        return {
            "pending": self.pending,
            "next_seq": self._next_seq,
            "timeout_ms": round(self.timeout_s * 1000, 1),
            "capacity": self.capacity,
            "stats": self.stats.as_dict(),
        }
