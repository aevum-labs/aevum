"""
CircuitBreaker — per-complication threshold-based circuit breaker.

States: CLOSED (normal) → OPEN (tripped) → HALF_OPEN (testing recovery).
Uses monotonic clock — no clock drift issues.
"""

from __future__ import annotations

import threading
import time
from enum import Enum, auto


class CBState(Enum):
    CLOSED    = auto()  # Normal — calls pass through
    OPEN      = auto()  # Tripped — calls fail immediately
    HALF_OPEN = auto()  # Recovery probe — one call allowed


class CircuitBreaker:
    """
    Thread-safe circuit breaker for a single complication.

    Args:
        failure_threshold: Consecutive failures before opening (default 5)
        recovery_seconds: Seconds before attempting half-open probe (default 30)
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_seconds: float = 30.0,
    ) -> None:
        self._threshold = failure_threshold
        self._recovery = recovery_seconds
        self._state = CBState.CLOSED
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CBState:
        with self._lock:
            self._check_recovery()
            return self._state

    @property
    def is_open(self) -> bool:
        return self.state == CBState.OPEN

    def record_success(self) -> None:
        """Call after a successful complication invocation."""
        with self._lock:
            self._failures = 0
            self._state = CBState.CLOSED
            self._opened_at = None

    def record_failure(self) -> None:
        """Call after a failed complication invocation."""
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._state = CBState.OPEN
                self._opened_at = time.monotonic()

    def allow_request(self) -> bool:
        """Return True if a request should be allowed through."""
        with self._lock:
            self._check_recovery()
            return self._state in (CBState.CLOSED, CBState.HALF_OPEN)

    def _check_recovery(self) -> None:
        """Transition OPEN → HALF_OPEN if recovery period has elapsed."""
        if self._state == CBState.OPEN and self._opened_at is not None and time.monotonic() - self._opened_at >= self._recovery:
            self._state = CBState.HALF_OPEN

    def reset(self) -> None:
        """Manual reset — for admin use."""
        with self._lock:
            self._state = CBState.CLOSED
            self._failures = 0
            self._opened_at = None
