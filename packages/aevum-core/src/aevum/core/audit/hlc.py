"""
HybridLogicalClock — causal ordering. Spec Section 06.5.
Timestamp: bits 63-16 = ms since epoch, bits 15-0 = logical counter.
"""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_last_ms: int = 0
_counter: int = 0


def now() -> int:
    global _last_ms, _counter
    with _lock:
        ms = int(time.time() * 1000)
        if ms > _last_ms:
            _last_ms = ms
            _counter = 0
        else:
            _counter += 1
            if _counter > 0xFFFF:
                _last_ms += 1
                _counter = 0
        return (_last_ms << 16) | _counter


def to_millis(ts: int) -> int:
    return ts >> 16


def to_counter(ts: int) -> int:
    return ts & 0xFFFF
