# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
ReplayEngine — deterministic re-execution and session diffing.

replay(session_id):
    Re-execute all events from a session in order.
    Compare current output_hash with stored output_hash at each step.
    Returns a ReplayResult with match/diverge status per event.

fork_at_step(session_id, step_n, override_metadata):
    Create a new session starting from step N of an existing session.
    Returns a new session_id for the forked execution.

diff(session_id_1, session_id_2):
    Compare two sessions and return the first divergence point.
    Used to compare an original session with its fork.

Phase 4 replay is hash-verification only: it re-reads stored events and
verifies the Merkle root matches what was recorded at REMEMBER time.
Full functional replay (re-calling RELATE/NAVIGATE/GOVERN with stored inputs)
is deferred to Phase 5.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aevum.core.session_record import CommitType, EventType, SessionEvent, SessionRecord

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class EventReplayResult:
    """The result of replaying a single event."""
    event_id: str
    sequence: int
    event_type: EventType
    stored_output_hash: str
    replayed_output_hash: str
    matched: bool

    @property
    def diverged(self) -> bool:
        return not self.matched


@dataclasses.dataclass(frozen=True)
class ReplayResult:
    """The complete result of replaying a session."""
    session_id: str
    original_merkle_root: str
    replayed_merkle_root: str
    event_results: tuple[EventReplayResult, ...]
    first_divergence: int | None    # sequence number of first diverged event, or None
    all_matched: bool

    @classmethod
    def from_event_results(
        cls,
        session_id: str,
        original_merkle_root: str,
        results: list[EventReplayResult],
    ) -> ReplayResult:
        event_results = tuple(results)
        first_div = next(
            (r.sequence for r in results if r.diverged), None
        )
        replayed_root = (
            hashlib.sha256(
                "".join(r.replayed_output_hash for r in results).encode("ascii")
            ).hexdigest()
            if results
            else hashlib.sha256(b"").hexdigest()
        )
        return cls(
            session_id=session_id,
            original_merkle_root=original_merkle_root,
            replayed_merkle_root=replayed_root,
            event_results=event_results,
            first_divergence=first_div,
            all_matched=first_div is None,
        )


@dataclasses.dataclass(frozen=True)
class DiffResult:
    """The difference between two sessions."""
    session_id_a: str
    session_id_b: str
    first_divergence: int | None    # sequence number where they diverge
    events_in_a: int
    events_in_b: int
    identical: bool
    downstream_effects: tuple[int, ...]   # sequence numbers of downstream diverged events


# SQLite schema (same as in session.py — created on demand)
_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id          TEXT PRIMARY KEY,
    commit_type         TEXT NOT NULL,
    principal           TEXT NOT NULL,
    purpose             TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    closed_at           TEXT NOT NULL,
    event_count         INTEGER NOT NULL,
    fact_count          INTEGER NOT NULL,
    checkpoint_count    INTEGER NOT NULL,
    merkle_root         TEXT NOT NULL,
    mldsa65_sig         TEXT,
    mldsa65_pub         TEXT,
    tsa_token           TEXT,
    sigchain_entry_id   INTEGER
)
"""

_CREATE_SESSION_EVENTS = """
CREATE TABLE IF NOT EXISTS session_events (
    event_id        TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    sequence        INTEGER NOT NULL,
    event_type      TEXT NOT NULL,
    occurred_at     TEXT NOT NULL,
    input_hash      TEXT NOT NULL,
    output_hash     TEXT NOT NULL,
    latency_ms      INTEGER NOT NULL
)
"""


class ReplayEngine:
    """
    Reads session records from SQLite and provides replay/diff operations.

    In Phase 4, replay is a verification operation: it re-reads the stored
    event hashes and verifies the session record is internally consistent.

    Full functional replay (actually re-calling RELATE/NAVIGATE/GOVERN
    with the stored inputs) requires the stored inputs to be available
    (encrypted in the consent store). This is the Phase 4 foundation;
    full re-execution with input injection is Phase 5.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute(_CREATE_SESSIONS)
        self._conn.execute(_CREATE_SESSION_EVENTS)
        self._conn.commit()

    def load_session_record(self, session_id: str) -> SessionRecord:
        """
        Load a SessionRecord from the SQLite sessions table.
        Raises ValueError if session_id not found.
        """
        row = self._conn.execute(
            "SELECT commit_type, principal, purpose, started_at, closed_at, "
            "merkle_root, sigchain_entry_id FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        if row is None:
            raise ValueError(f"Session not found: {session_id!r}")

        commit_type, principal, purpose, started_at_str, closed_at_str, \
            merkle_root, sigchain_entry_id = row

        event_rows = self._conn.execute(
            "SELECT event_id, sequence, event_type, occurred_at, "
            "input_hash, output_hash, latency_ms "
            "FROM session_events WHERE session_id = ? ORDER BY sequence",
            (session_id,),
        ).fetchall()

        events = tuple(
            SessionEvent(
                event_id=r[0],
                session_id=session_id,
                sequence=r[1],
                event_type=EventType(r[2]),
                occurred_at=datetime.fromisoformat(r[3]),
                input_hash=r[4],
                output_hash=r[5],
                latency_ms=r[6],
                taint_labels=(),
            )
            for r in event_rows
        )

        return SessionRecord(
            session_id=session_id,
            commit_type=CommitType(commit_type),
            principal=principal,
            purpose=purpose,
            started_at=datetime.fromisoformat(started_at_str),
            closed_at=datetime.fromisoformat(closed_at_str),
            events=events,
            fact_ids=(),        # not stored separately in Phase 4
            checkpoint_ids=(),  # not stored separately in Phase 4
            merkle_root=merkle_root,
            sigchain_entry_id=sigchain_entry_id,
        )

    def replay(self, session_id: str) -> ReplayResult:
        """
        Verify a session record by recomputing its Merkle root.

        Phase 4 replay: re-reads stored events and verifies the Merkle root
        matches what was recorded at REMEMBER time. This confirms the event
        sequence has not been tampered with.

        Phase 5+ will add full functional replay (re-executing each step).
        """
        record = self.load_session_record(session_id)

        results: list[EventReplayResult] = []
        for event in record.events:
            results.append(EventReplayResult(
                event_id=event.event_id,
                sequence=event.sequence,
                event_type=event.event_type,
                stored_output_hash=event.output_hash,
                replayed_output_hash=event.output_hash,   # Phase 4: same (verification mode)
                matched=True,
            ))

        # Verify the stored Merkle root matches the recomputed one
        recomputed_root = SessionRecord.compute_merkle_root(record.events)
        root_matches = (recomputed_root == record.merkle_root)

        if not root_matches:
            logger.error(
                "REPLAY: Merkle root mismatch for session %s. "
                "Stored: %s, Recomputed: %s. Tampering suspected.",
                session_id, record.merkle_root[:8], recomputed_root[:8],
            )
            results = [
                dataclasses.replace(r, matched=False)
                for r in results
            ]

        return ReplayResult.from_event_results(
            session_id=session_id,
            original_merkle_root=record.merkle_root,
            results=results,
        )

    def diff(self, session_id_a: str, session_id_b: str) -> DiffResult:
        """
        Compare two sessions event-by-event.
        Returns the first divergence point and downstream effects.

        Useful for comparing an original session with its fork.
        """
        record_a = self.load_session_record(session_id_a)
        record_b = self.load_session_record(session_id_b)

        events_a = record_a.events
        events_b = record_b.events

        first_divergence: int | None = None
        downstream: list[int] = []

        n = max(len(events_a), len(events_b))
        for i in range(n):
            if i >= len(events_a) or i >= len(events_b):
                if first_divergence is None:
                    first_divergence = i
                downstream.append(i)
                continue

            ea, eb = events_a[i], events_b[i]
            if ea.output_hash != eb.output_hash or ea.event_type != eb.event_type:
                if first_divergence is None:
                    first_divergence = ea.sequence
                downstream.append(ea.sequence)

        return DiffResult(
            session_id_a=session_id_a,
            session_id_b=session_id_b,
            first_divergence=first_divergence,
            events_in_a=len(events_a),
            events_in_b=len(events_b),
            identical=(first_divergence is None and len(events_a) == len(events_b)),
            downstream_effects=tuple(downstream),
        )

    def fork_at_step(
        self,
        session_id: str,
        step_n: int,
        override_metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new session record branching from step N of an existing session.

        The fork inherits all events from session_id up to (exclusive) step_n.
        Events at step_n and beyond are replaced by the caller.

        Phase 4: creates the fork record with inherited events.
        Actual re-execution with different inputs is Phase 5.

        Returns: new fork session_id
        """
        record = self.load_session_record(session_id)

        if step_n < 0 or step_n > len(record.events):
            raise ValueError(
                f"step_n={step_n} out of range for session with "
                f"{len(record.events)} events"
            )

        inherited_events = record.events[:step_n]
        fork_id = f"fork-{str(uuid.uuid4())}"
        merkle_root = SessionRecord.compute_merkle_root(inherited_events)

        fork_record = SessionRecord(
            session_id=fork_id,
            commit_type=CommitType.PARTIAL,
            principal=record.principal,
            purpose=f"fork of {session_id} at step {step_n}",
            started_at=datetime.now(UTC),
            closed_at=datetime.now(UTC),
            events=inherited_events,
            fact_ids=(),
            checkpoint_ids=(),
            merkle_root=merkle_root,
        )

        self._write_fork_record(fork_record)

        logger.info(
            "FORK: session=%s step=%d fork_id=%s inherited_events=%d",
            session_id, step_n, fork_id, len(inherited_events),
        )
        return fork_id

    def _write_fork_record(self, record: SessionRecord) -> None:
        """Write a fork session record to the sessions table."""
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions VALUES "
            "(?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
            (
                record.session_id,
                record.commit_type.value,
                record.principal,
                record.purpose,
                record.started_at.isoformat(),
                record.closed_at.isoformat(),
                len(record.events),
                len(record.fact_ids),
                len(record.checkpoint_ids),
                record.merkle_root,
            ),
        )
        for ev in record.events:
            # Use fork-qualified event_id to avoid PK collision with the original session
            fork_event_id = f"{record.session_id}-seq{ev.sequence}"
            self._conn.execute(
                "INSERT OR REPLACE INTO session_events "
                "(event_id, session_id, sequence, event_type, occurred_at, "
                "input_hash, output_hash, latency_ms) VALUES (?,?,?,?,?,?,?,?)",
                (
                    fork_event_id, record.session_id, ev.sequence,
                    ev.event_type.value, ev.occurred_at.isoformat(),
                    ev.input_hash, ev.output_hash, ev.latency_ms,
                ),
            )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
