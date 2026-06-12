# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Session — per-request context carrier and the REMEMBER (commit) write path.

Session accumulates RELATE/NAVIGATE/GOVERN events within one logical episode context.
On __aexit__ it seals the episode: Merkle root over all events, optional dual-sign,
optional RFC 3161 timestamp, SQLite persist, and a sigchain append.

Lifecycle (always use as an async context manager):
  async with Session(actor="...", kernel=kernel, db_path=path) as session:
      engine.ingest(..., session=session)   # RELATE — events accumulate
      engine.query(..., session=session)    # NAVIGATE — events accumulate
      engine.review(..., session=session)   # GOVERN — events accumulate
  # __aexit__: _remember() fires, seals the episode

REMEMBER always fires on __aexit__ regardless of exception type (including BarrierError —
a crisis session still gets committed so the crisis record is in the episodic ledger).
If _remember() itself fails, the failure is logged at ERROR level and session close
is not blocked — an incomplete REMEMBER is a principle violation, not a crash.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Session records are persisted to SQLite rather than the Oxigraph provenance graph because
# receipt blobs (COSE_Sign1 bytes) and Merkle root payloads are binary and can be tens of
# kilobytes — too large for efficient RDF xsd:base64Binary triple-store storage. SQLite in
# WAL mode provides append-only semantics, fast range queries by session_id, and atomic
# commits without the overhead of a triple store. See the Session 2 SQLite WAL plan.
# SQLite schema for session records
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
    sigchain_entry_id   TEXT
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


@dataclasses.dataclass
class Session:
    """Per-request context carrier. Accumulates events and seals the episode on close.

    Field split by development phase:
      Phase 1 fields (actor, correlation_id, episode_id, trace_id, span_id, metadata):
        Always present. Identify the principal and provide distributed tracing context.
        These cannot be removed without breaking backward compatibility (S-12 sigchain fields).
      Phase 4 fields (purpose, kernel, db_path):
        All optional. If kernel is None, REMEMBER still fires but skips dual-signing and
        TSA timestamping. If db_path is None, the session record is not written to SQLite.
        This allows lightweight in-memory sessions that still produce a sigchain entry.
    """
    # Original Phase 1 fields (unchanged — backward compatible)
    actor: str
    correlation_id: str | None = None
    episode_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    # Phase 4 bindings — optional; if absent, REMEMBER still fires but skips signing/SQLite
    purpose: str = ""
    kernel: Any = None       # aevum.core.kernel.Kernel | None
    db_path: Any = None      # pathlib.Path | None

    def __post_init__(self) -> None:
        self._session_id: str = self.episode_id or str(uuid.uuid4())
        self._events: list[Any] = []     # list[SessionEvent]
        self._fact_ids: list[str] = []
        self._checkpoint_ids: list[str] = []
        self._started_at: datetime = datetime.now(UTC)
        self._principal: str = self.actor

    # Async context manager protocol: __aenter__ returns self immediately (no setup needed at
    # entry); __aexit__ is where REMEMBER fires. All RELATE/NAVIGATE/GOVERN events accumulate
    # in self._events during the body of the `async with` block and are committed as a single
    # sealed unit on exit. This guarantees that the session record reflects the complete
    # episode, not a partial view from an intermediate commit.
    async def __aenter__(self) -> Session:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        # Determine CommitType from how the session closed
        if exc_type is None:
            commit_type = "complete"
        else:
            try:
                from aevum.core.barriers import BarrierError
                commit_type = "crisis" if issubclass(exc_type, BarrierError) else "emergency"
            except ImportError:
                commit_type = "emergency"
        # REMEMBER fires here regardless — never blocks session close
        await self._remember(commit_type=commit_type)

    async def _remember(self, commit_type: str) -> None:
        """Seal the episode: Merkle root → dual-sign → TSA → SQLite → sigchain. Called by __aexit__.

        Implementation steps (numbered comments in body):
          1. Collect all accumulated SessionEvent records into an immutable tuple.
          2. Compute Merkle root (SHA3-256 pairwise tree) over all events. A Merkle root
             rather than a simple hash of the last event means any individual event can be
             proven present or absent without replaying the full session history.
          3. Build a SessionRecord and serialize to RFC 8785 JCS canonical JSON for signing.
          4. Dual-sign with Ed25519 (tamper-detection) and ML-DSA-65 (post-quantum
             tamper-detection). Non-blocking: signing failure is logged but does not abort.
          5. RFC 3161 timestamp — circuit-breaker pattern; TSA outage never blocks close.
          6. Write session row and per-event rows to SQLite (if db_path is configured).
          7. Append "session.committed" to the kernel sigchain (if kernel is configured).

        This method must never raise. A REMEMBER failure must not prevent __aexit__ from
        completing — leaving a session in limbo would corrupt subsequent episode accounting.
        Any failure is logged at ERROR level and is a principle violation requiring triage.
        """
        try:
            from aevum.core.session_record import CommitType, SessionRecord

            # 1. Collect accumulated events
            events = tuple(self._events)

            # 2. Compute Merkle root
            merkle_root = SessionRecord.compute_merkle_root(events)

            # 3. Build SessionRecord — purpose defaults to actor if not set
            effective_purpose = self.purpose or f"session/{self._principal}"
            record = SessionRecord(
                session_id=self._session_id,
                commit_type=CommitType(commit_type),
                principal=self._principal,
                purpose=effective_purpose,
                started_at=self._started_at,
                closed_at=datetime.now(UTC),
                events=events,
                fact_ids=tuple(self._fact_ids),
                checkpoint_ids=tuple(self._checkpoint_ids),
                merkle_root=merkle_root,
            )

            # 4. Serialize for signing
            payload = json.dumps(
                record.to_dict(), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")

            # 5. Dual-sign (Ed25519 + ML-DSA-65) — non-blocking
            dual_sig = None
            if self.kernel is not None:
                try:
                    dual_sig = self.kernel.signer.sign(payload)
                except Exception as exc:  # noqa: BLE001
                    logger.error("REMEMBER: dual-sign failed for session %s: %s", self._session_id, exc)

            # 6. RFC 3161 timestamp — circuit-breaker, never raises
            tsa_hex: str | None = None
            if self.kernel is not None and dual_sig is not None:
                try:
                    tsa_token = self.kernel.tsa_client.timestamp(payload)
                    tsa_hex = tsa_token.token_bytes.hex() if tsa_token else None
                except Exception as exc:  # noqa: BLE001
                    logger.warning("REMEMBER: TSA failed for session %s: %s", self._session_id, exc)

            # 7. Write to SQLite sessions + session_events tables
            self._write_session_record(record, dual_sig, tsa_hex)

            # 8. Append to sigchain (optional — uses kernel if available)
            sigchain_event_id = self._append_to_sigchain(record, dual_sig, tsa_hex)

            # 9. Update sigchain_entry_id now that we have the canonical chain entry id
            if sigchain_event_id is not None:
                self._update_sigchain_entry_id(record.session_id, sigchain_event_id)

            logger.info(
                "REMEMBER: session=%s commit_type=%s events=%d merkle=%s...",
                self._session_id, commit_type, len(events), merkle_root[:8],
            )

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "REMEMBER FAILED for session %s commit_type=%s: %s. "
                "This is a principle violation and must be investigated.",
                self._session_id, commit_type, exc,
            )

    def _write_session_record(
        self,
        record: Any,          # SessionRecord
        dual_sig: Any,        # DualSignature | None
        tsa_hex: str | None,
    ) -> int | None:
        """Write session record and events to SQLite. Returns rowid or None."""
        if self.db_path is None:
            return None
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(_CREATE_SESSIONS)
            conn.execute(_CREATE_SESSION_EVENTS)

            mldsa65_sig = dual_sig.mldsa65_sig.hex() if dual_sig else None
            mldsa65_pub = dual_sig.mldsa65_pub.hex() if dual_sig else None

            cursor = conn.execute(
                "INSERT OR REPLACE INTO sessions VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    mldsa65_sig,
                    mldsa65_pub,
                    tsa_hex,
                    None,  # sigchain_entry_id populated after sigchain append
                ),
            )
            for ev in record.events:
                conn.execute(
                    "INSERT OR IGNORE INTO session_events "
                    "(event_id, session_id, sequence, event_type, occurred_at, "
                    "input_hash, output_hash, latency_ms) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        ev.event_id,
                        record.session_id,
                        ev.sequence,
                        ev.event_type.value,
                        ev.occurred_at.isoformat(),
                        ev.input_hash,
                        ev.output_hash,
                        ev.latency_ms,
                    ),
                )
            conn.commit()
            rowid = cursor.lastrowid
            conn.close()
            return rowid
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "REMEMBER: SQLite write failed for session %s: %s",
                self._session_id, exc,
            )
            return None

    def _append_to_sigchain(
        self,
        record: Any,
        dual_sig: Any,
        tsa_hex: str | None,
    ) -> str | None:
        """Append session commit event to the kernel sigchain if available.

        Returns the AuditEvent.event_id of the appended entry (for sigchain_entry_id),
        or None if no sigchain is configured or the append fails.
        """
        if self.kernel is None:
            return None
        try:
            payload: dict[str, Any] = {
                "session_id": record.session_id,
                "commit_type": record.commit_type.value,
                "merkle_root": record.merkle_root,
                "event_count": len(record.events),
            }
            sigchain = getattr(self.kernel, "sigchain", None)
            if sigchain is not None:
                event = sigchain.new_event(
                    event_type="session.committed",
                    payload=payload,
                    actor=self._principal,
                    episode_id=self._session_id,
                )
                return str(event.event_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "REMEMBER: sigchain append failed for session %s: %s",
                self._session_id, exc,
            )
        return None

    def _update_sigchain_entry_id(self, session_id: str, sigchain_event_id: str) -> None:
        """Update the sigchain_entry_id column for an already-written session row."""
        if self.db_path is None:
            return
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(
                "UPDATE sessions SET sigchain_entry_id = ? WHERE session_id = ?",
                (sigchain_event_id, session_id),
            )
            conn.commit()
            conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "REMEMBER: sigchain_entry_id update failed for session %s: %s",
                session_id, exc,
            )

    # ── Event recording ───────────────────────────────────────────────────────

    def _record_event(
        self,
        event_type: Any,       # EventType
        input_hash: str,
        output_hash: str,
        latency_ms: int = 0,
        taint_labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Append a SessionEvent to the in-flight events list."""
        try:
            from aevum.core.session_record import EventType, SessionEvent
            seq = len(self._events)
            ev = SessionEvent(
                event_id=str(uuid.uuid4()),
                session_id=self._session_id,
                sequence=seq,
                event_type=EventType(event_type) if isinstance(event_type, str) else event_type,
                occurred_at=datetime.now(UTC),
                input_hash=input_hash,
                output_hash=output_hash,
                latency_ms=latency_ms,
                taint_labels=taint_labels,
                metadata=metadata or {},
            )
            self._events.append(ev)
        except Exception as exc:  # noqa: BLE001
            logger.error("Session._record_event failed: %s", exc)

    def record_relate_event(
        self,
        input_hash: str,
        output_hash: str,
        fact_id: str | None = None,
        latency_ms: int = 0,
        taint_labels: tuple[str, ...] = (),
    ) -> None:
        """Record a RELATE (ingest) call. Appends fact_id if provided."""
        from aevum.core.session_record import EventType
        self._record_event(EventType.RELATE, input_hash, output_hash, latency_ms, taint_labels)
        if fact_id:
            self._fact_ids.append(fact_id)

    def record_navigate_event(
        self,
        input_hash: str,
        output_hash: str,
        latency_ms: int = 0,
        taint_labels: tuple[str, ...] = (),
    ) -> None:
        """Record a NAVIGATE (query) call."""
        from aevum.core.session_record import EventType
        self._record_event(EventType.NAVIGATE, input_hash, output_hash, latency_ms, taint_labels)

    def record_govern_event(
        self,
        input_hash: str,
        output_hash: str,
        checkpoint_id: str | None = None,
        latency_ms: int = 0,
        taint_labels: tuple[str, ...] = (),
    ) -> None:
        """Record a GOVERN checkpoint call. Appends checkpoint_id if provided."""
        from aevum.core.session_record import EventType
        self._record_event(EventType.GOVERN, input_hash, output_hash, latency_ms, taint_labels)
        if checkpoint_id:
            self._checkpoint_ids.append(checkpoint_id)
