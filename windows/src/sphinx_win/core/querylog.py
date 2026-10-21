"""A short, on-device record of recent DNS queries: what was asked,
and whether Sphinx blocked it.

A port of the Android edition's ``core/QueryLog.kt``. Privacy rules
(FILTER-SPEC, honesty rules):

- The log lives only in memory on the device. It is never written to
  disk by the filter, never transmitted anywhere, and it is gone when
  the process dies.
- It is a ring buffer with a hard cap, so it can never grow without
  bound: once full, each new entry pushes out the oldest.
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass

DEFAULT_CAPACITY = 500


@dataclass(frozen=True)
class QueryLogEntry:
    name: str
    blocked: bool
    timestamp_ms: int


class QueryLog:
    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        if capacity <= 0:
            raise ValueError("query log capacity must be positive")
        self._entries: deque = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def record(self, name: str, blocked: bool, timestamp_ms: int) -> None:
        with self._lock:
            self._entries.append(QueryLogEntry(name, blocked, timestamp_ms))

    def snapshot(self) -> list:
        """Newest first. A copy — callers can't mutate the log."""
        with self._lock:
            return list(reversed(self._entries))

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
