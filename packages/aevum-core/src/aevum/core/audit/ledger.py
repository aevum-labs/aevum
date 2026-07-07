# SPDX-License-Identifier: Apache-2.0
"""
Episodic ledger — append-only. Barrier 4 enforced here. Spec Section 06.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import Sigchain
from aevum.core.exceptions import BarrierViolationError, ReplayNotFoundError

if TYPE_CHECKING:
    from aevum.core.audit.commitment_key_store import CommitmentKeyStore


class InMemoryLedger:
    """Thread-safe append-only in-memory episodic ledger. Suitable for development and testing."""

    def __init__(
        self,
        sigchain: Sigchain,
        commitment_key_store: CommitmentKeyStore | None = None,
    ) -> None:
        self._sigchain = sigchain
        self._commitment_key_store = commitment_key_store
        self._events: list[AuditEvent] = []
        self._index: dict[str, AuditEvent] = {}
        self._lock = threading.Lock()
        self._observers: list[Any] = []

    def add_observer(self, observer: Any) -> None:
        """
        Register an observer to be called after each successful append.
        Observer must implement on_event(event: AuditEvent) -> None.
        Observer errors are logged and suppressed — they must not interrupt the sigchain.
        """
        with self._lock:
            self._observers.append(observer)

    def append(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        episode_id: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        principal_identity: str | None = None,
        principal_claims: dict[str, Any] | None = None,
        commitment_key_id: str | None = None,
    ) -> AuditEvent:
        from aevum.core.audit.commitment_key_store import resolve_commitment_key

        commitment_key = resolve_commitment_key(
            self._commitment_key_store,
            principal_identity=principal_identity,
            commitment_key_id=commitment_key_id,
        )
        with self._lock:
            event = self._sigchain.new_event(
                event_type=event_type,
                payload=payload,
                actor=actor,
                episode_id=episode_id,
                causation_id=causation_id,
                correlation_id=correlation_id,
                principal_identity=principal_identity,
                principal_claims=principal_claims,
                commitment_key_id=commitment_key_id,
                commitment_key=commitment_key,
            )
            self._events.append(event)
            self._index[event.audit_id()] = event
            observers = list(self._observers)

        import logging as _logging
        _obs_log = _logging.getLogger("aevum.core.ledger")
        for obs in observers:
            try:
                obs.on_event(event)
            except Exception as exc:  # noqa: BLE001
                _obs_log.error("ledger observer error (suppressed): %s", exc)
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

    def restore_events(self, events: list[AuditEvent]) -> None:
        """
        Re-hydrate already-signed events from persisted storage without
        re-signing them. Mirrors PostgresLedger._resume_chain_from_db() --
        never calls new_event(); never re-derives valid_from, system_time,
        signature, or hash. Call once at startup, before serving requests,
        with events in original commit order.
        """
        if not events:
            return
        with self._lock:
            for e in events:
                self._events.append(e)
                self._index[e.audit_id()] = e
            last = events[-1]
            continuation_hash = AuditEvent.hash_event_for_chain(last)
            self._sigchain.restore((last.sequence, continuation_hash))

    def last_audit_id(self) -> str | None:
        all_ev = self.all_events()
        if not all_ev:
            return None
        return all_ev[-1].audit_id()

    def max_sequence_for_subjects(self, subject_ids: list[str]) -> int:
        """
        Return the highest sequence number among all ingest events
        whose payload["subject_id"] is in subject_ids.
        Returns 0 if no matching events exist.
        """
        with self._lock:
            best = 0
            for event in self._events:
                if event.event_type == "ingest.accepted":
                    sid = event.payload.get("subject_id", "")
                    if sid in subject_ids and event.sequence > best:
                        best = event.sequence
            return best

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
