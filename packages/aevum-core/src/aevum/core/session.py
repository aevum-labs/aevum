# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Session — per-request context carrier with async context manager."""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

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
    ed25519_sig         TEXT,
    mldsa65_sig         TEXT,
    ed25519_pub         TEXT,
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


@dataclasses.dataclass
class Session:
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
        """
        Mandatory COMMIT on session close. Called by __aexit__.
        Must not raise — if it fails, log and continue.
        Session close must not be blocked by a REMEMBER failure.
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
            entry_id = self._write_session_record(record, dual_sig, tsa_hex)

            # 8. Append to sigchain (optional — uses kernel if available)
            self._append_to_sigchain(record, dual_sig, tsa_hex)

            logger.info(
                "REMEMBER: session=%s commit_type=%s events=%d merkle=%s...",
                self._session_id, commit_type, len(events), merkle_root[:8],
            )
            _ = entry_id  # used for gate report; could be None if no db_path

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

            ed25519_sig = dual_sig.ed25519_sig.hex() if dual_sig else None
            mldsa65_sig = dual_sig.mldsa65_sig.hex() if dual_sig else None
            ed25519_pub = dual_sig.ed25519_pub.hex() if dual_sig else None
            mldsa65_pub = dual_sig.mldsa65_pub.hex() if dual_sig else None

            cursor = conn.execute(
                "INSERT OR REPLACE INTO sessions VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    ed25519_sig,
                    mldsa65_sig,
                    ed25519_pub,
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
    ) -> None:
        """Append session commit event to the kernel sigchain if available."""
        if self.kernel is None:
            return
        try:
            payload: dict[str, Any] = {
                "session_id": record.session_id,
                "commit_type": record.commit_type.value,
                "merkle_root": record.merkle_root,
                "event_count": len(record.events),
            }
            if hasattr(self.kernel, "_sigchain") or hasattr(self.kernel, "sigchain"):
                sigchain = getattr(self.kernel, "_sigchain", None) or getattr(self.kernel, "sigchain", None)
                if sigchain is not None:
                    sigchain.new_event(
                        event_type="session.committed",
                        payload=payload,
                        actor=self._principal,
                        episode_id=self._session_id,
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "REMEMBER: sigchain append failed for session %s: %s",
                self._session_id, exc,
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
