"""Logging configuration plus an in-memory ring buffer the web UI streams from."""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections import deque
from collections.abc import Iterable
from typing import Any

LOGGER_NAME = "turbobond"
_MAX_RECORDS = 2000


class RingBufferHandler(logging.Handler):
    """Keeps the most recent log records so the dashboard can replay them."""

    def __init__(self, capacity: int = _MAX_RECORDS) -> None:
        super().__init__()
        self._records: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._seq = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            message = str(record.msg)
        with self._lock:
            self._seq += 1
            self._records.append(
                {
                    "seq": self._seq,
                    "ts": record.created,
                    "level": record.levelname,
                    "logger": record.name,
                    "message": message,
                }
            )

    def tail(self, after_seq: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            items = [r for r in self._records if r["seq"] > after_seq]
        return items[-limit:]

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


ring_buffer = RingBufferHandler()


class _ElapsedFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
        self._start = time.time()


_configured = False


def configure(level: int | str = logging.INFO, *, extra_handlers: Iterable[logging.Handler] = ()) -> None:
    """Install stderr + ring-buffer handlers exactly once."""

    global _configured
    root = logging.getLogger(LOGGER_NAME)
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())
        if not isinstance(level, int):
            level = logging.INFO
    root.setLevel(level)
    if _configured:
        return

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(_ElapsedFormatter())
    root.addHandler(stream)

    ring_buffer.setFormatter(_ElapsedFormatter())
    root.addHandler(ring_buffer)

    for handler in extra_handlers:
        root.addHandler(handler)

    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the turbobond root logger."""

    if name.startswith(LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
