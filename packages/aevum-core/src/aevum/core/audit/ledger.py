"""
Episodic ledger — append-only. Barrier 4 enforced here. Spec Section 06.
"""

from __future__ import annotations

import threading
from typing import Any

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import Sigchain
from aevum.core.exceptions import BarrierViolationError, ReplayNotFoundError


class InMemoryLedger:
    """Thread-safe append-only in-memory episodic ledger. Suitable for development and testing."""

    def __init__(self, sigchain: Sigchain) -> None:
        self._sigchain = sigchain
        self._events: list[AuditEvent] = []
        self._index: dict[str, AuditEvent] = {}
        self._lock = threading.Lock()

    def append(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        episode_id: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        with self._lock:
            event = self._sigchain.new_event(
                event_type=event_type,
                payload=payload,
                actor=actor,
                episode_id=episode_id,
                causation_id=causation_id,
                correlation_id=correlation_id,
            )
            self._events.append(event)
            self._index[event.audit_id()] = event
            return event

    def get(self, audit_id: str) -> AuditEvent:
        event = self._index.get(audit_id)
        if event is None:
            raise ReplayNotFoundError(f"No ledger entry for {audit_id!r}")
        return event

    def all_events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def last_audit_id(self) -> str | None:
        all_ev = self.all_events()
        if not all_ev:
            return None
        return all_ev[-1].audit_id()

    def __delitem__(self, key: object) -> None:
        """Barrier 4: deletion forbidden."""
        raise BarrierViolationError(
            "Attempted to delete a ledger entry — Barrier 4 (Audit Immutability) violated."
        )

    def __setitem__(self, key: object, value: object) -> None:
        """Barrier 4: overwrite forbidden."""
        raise BarrierViolationError(
            "Attempted to overwrite a ledger entry — Barrier 4 (Audit Immutability) violated."
        )
