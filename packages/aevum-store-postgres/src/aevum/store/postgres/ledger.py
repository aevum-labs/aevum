"""
PostgresLedger -- persistent episodic ledger backed by PostgreSQL.

AuditEvents are serialized as JSONB. Sigchain verification still works --
verify_chain() reads all events in sequence order from Postgres.

Barrier 4 (Audit Immutability) enforced by __delitem__ and __setitem__.
The database table is INSERT-only -- no UPDATE or DELETE ever issued.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import Sigchain
from aevum.core.exceptions import BarrierViolationError, ReplayNotFoundError

_DDL_LEDGER = """
CREATE TABLE IF NOT EXISTS aevum_ledger (
    sequence        BIGSERIAL PRIMARY KEY,
    event_id        TEXT NOT NULL UNIQUE,
    audit_id        TEXT NOT NULL UNIQUE,
    event_type      TEXT NOT NULL,
    actor           TEXT NOT NULL,
    system_time     BIGINT NOT NULL,
    episode_id      TEXT,
    causation_id    TEXT,
    correlation_id  TEXT,
    prior_hash      TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    signature       TEXT NOT NULL,
    signer_key_id   TEXT NOT NULL,
    schema_version  TEXT NOT NULL DEFAULT '1.0',
    valid_from      TEXT NOT NULL,
    valid_to        TEXT,
    trace_id        TEXT,
    span_id         TEXT,
    payload         JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aevum_ledger_audit_id ON aevum_ledger (audit_id);
CREATE INDEX IF NOT EXISTS idx_aevum_ledger_sequence ON aevum_ledger (sequence);
"""


def initialize_ledger_schema(conn: Any) -> None:
    """Create the aevum_ledger table if it does not exist."""
    with conn.cursor() as cur:
        cur.execute(_DDL_LEDGER)
    conn.commit()


def _event_to_row(event: AuditEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "audit_id": event.audit_id(),
        "event_type": event.event_type,
        "actor": event.actor,
        "system_time": event.system_time,
        "episode_id": event.episode_id,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "prior_hash": event.prior_hash,
        "payload_hash": event.payload_hash,
        "signature": event.signature,
        "signer_key_id": event.signer_key_id,
        "schema_version": event.schema_version,
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "payload": json.dumps(event.payload, default=str),
    }


def _row_to_event(row: dict[str, Any]) -> AuditEvent:
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return AuditEvent(
        event_id=row["event_id"],
        episode_id=row.get("episode_id", ""),
        sequence=row["sequence"],
        event_type=row["event_type"],
        schema_version=row.get("schema_version", "1.0"),
        valid_from=row["valid_from"],
        valid_to=row.get("valid_to"),
        system_time=row["system_time"],
        causation_id=row.get("causation_id"),
        correlation_id=row.get("correlation_id"),
        actor=row["actor"],
        trace_id=row.get("trace_id"),
        span_id=row.get("span_id"),
        payload=payload,
        payload_hash=row["payload_hash"],
        prior_hash=row["prior_hash"],
        signature=row["signature"],
        signer_key_id=row["signer_key_id"],
    )


class PostgresLedger:
    """
    Persistent episodic ledger backed by PostgreSQL.

    Thread-safe. INSERT-only (Barrier 4 at application layer).
    Pass a shared threading.Lock if sharing a connection with PostgresStore.
    """

    def __init__(
        self,
        conn: Any,
        sigchain: Sigchain,
        lock: threading.Lock | None = None,
    ) -> None:
        self._conn = conn
        self._sigchain = sigchain
        self._lock = lock or threading.Lock()
        self._resume_chain_from_db()

    def _resume_chain_from_db(self) -> None:
        """
        Seed the in-memory sigchain state from the last persisted event.

        Without this, every Engine restart begins a new chain at
        sequence=1 / prior_hash=GENESIS_HASH, silently forking the chain.
        After this fix, the sigchain continues from where the last process left off.

        Idempotent — safe to call on a fresh database (no-op if table empty).
        """
        from psycopg.rows import dict_row

        log = logging.getLogger(__name__)
        try:
            with self._lock, self._conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT sequence, event_id, audit_id,
                           event_type, actor, system_time,
                           episode_id, causation_id, correlation_id,
                           prior_hash, payload_hash, signature,
                           signer_key_id, schema_version,
                           valid_from, valid_to,
                           trace_id, span_id, payload
                    FROM aevum_ledger
                    ORDER BY sequence DESC
                    LIMIT 1
                    """
                )
                row = cur.fetchone()
        except Exception as exc:
            log.debug(
                "aevum-store-postgres: could not resume chain from DB (%s) "
                "— starting from genesis. Normal on a fresh database.",
                exc,
            )
            return

        if row is None:
            return  # Fresh database — genesis is correct

        last_event = _row_to_event(row)
        continuation_hash = AuditEvent.hash_event_for_chain(last_event)
        self._sigchain.restore((last_event.sequence, continuation_hash))

        log.debug(
            "aevum-store-postgres: resumed chain from DB "
            "— sequence=%d prior_hash=%s…",
            last_event.sequence,
            continuation_hash[:12],
        )

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
            # Save sigchain state before advancing it.
            # If the INSERT fails, restore prevents the chain from
            # chaining from a ghost event that was never persisted.
            checkpoint = self._sigchain.checkpoint()
            event = self._sigchain.new_event(
                event_type=event_type,
                payload=payload,
                actor=actor,
                episode_id=episode_id,
                causation_id=causation_id,
                correlation_id=correlation_id,
            )
            row = _event_to_row(event)
            try:
                with self._conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO aevum_ledger (
                            event_id, audit_id, event_type, actor, system_time,
                            episode_id, causation_id, correlation_id,
                            prior_hash, payload_hash, signature, signer_key_id,
                            schema_version, valid_from, valid_to,
                            trace_id, span_id, payload
                        ) VALUES (
                            %(event_id)s, %(audit_id)s, %(event_type)s, %(actor)s,
                            %(system_time)s, %(episode_id)s, %(causation_id)s,
                            %(correlation_id)s, %(prior_hash)s, %(payload_hash)s,
                            %(signature)s, %(signer_key_id)s, %(schema_version)s,
                            %(valid_from)s, %(valid_to)s, %(trace_id)s,
                            %(span_id)s, %(payload)s::jsonb
                        )
                        """,
                        row,
                    )
                self._conn.commit()
            except Exception:
                self._sigchain.restore(checkpoint)
                raise
            return event

    def last_audit_id(self) -> str | None:
        """Return the audit_id of the most recently appended event, or None."""
        from psycopg.rows import dict_row

        with self._lock, self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT audit_id FROM aevum_ledger ORDER BY sequence DESC LIMIT 1"
            )
            row = cur.fetchone()
        return row["audit_id"] if row else None

    def get(self, audit_id: str) -> AuditEvent:
        from psycopg.rows import dict_row
        with self._lock, self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT * FROM aevum_ledger WHERE audit_id = %s",
                (audit_id,),
            )
            row = cur.fetchone()
        if row is None:
            raise ReplayNotFoundError(f"No ledger entry for {audit_id!r}")
        return _row_to_event(row)

    def all_events(self) -> list[AuditEvent]:
        from psycopg.rows import dict_row
        with self._lock, self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM aevum_ledger ORDER BY sequence ASC")
            rows = cur.fetchall()
        return [_row_to_event(r) for r in rows]

    def count(self) -> int:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM aevum_ledger")
            result = cur.fetchone()
        return result[0] if result else 0

    def max_sequence_for_subjects(self, subject_ids: list[str]) -> int:
        """
        Return the highest sequence number among all ingest.accepted events
        whose payload subject_id is in subject_ids. Returns 0 if none found.
        """
        if not subject_ids:
            return 0
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(MAX(sequence), 0)
                FROM aevum_ledger
                WHERE event_type = 'ingest.accepted'
                  AND payload->>'subject_id' = ANY(%s)
                """,
                (subject_ids,),
            )
            result = cur.fetchone()
        return int(result[0]) if result else 0

    def __delitem__(self, key: object) -> None:
        raise BarrierViolationError(
            "Attempted to delete a ledger entry -- Barrier 4 (Audit Immutability) violated."
        )

    def __setitem__(self, key: object, value: object) -> None:
        raise BarrierViolationError(
            "Attempted to overwrite a ledger entry -- Barrier 4 (Audit Immutability) violated."
        )
