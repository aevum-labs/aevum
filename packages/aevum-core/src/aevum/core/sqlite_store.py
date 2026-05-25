# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
SqliteReceiptStore — three-tier receipt storage backed by SQLite WAL.

Three tiers, one SQLite file (AEVUM_RECEIPT_DB):
  crash_protected  locked=1; never rotated; DSSAD-equivalent survivor
  operational      default; 48-hour rolling window (configurable)
  long_term        EU AI Act Art. 26(6) minimum; promoted by rotate_operational()

SQLite WAL supports multiple readers but only one writer at a time.
Concurrent put() calls serialize — this is acceptable for single-process
deployments. For multi-process deployments, use PostgresReceiptStore (not yet
implemented; see adr-010-three-tier-receipt-storage.md).

rotate_operational() is a maintenance method; it is NOT called automatically.
Callers (cron job, maintenance session) must invoke it on a schedule.
Recommended: daily. Failure to run it will cause unbounded operational-tier growth.
"""

from __future__ import annotations

import sqlite3
import time

from aevum.core.store import ReceiptNotFoundError

_CREATE_RECEIPTS = """
CREATE TABLE IF NOT EXISTS receipts (
    receipt_hash    TEXT    NOT NULL PRIMARY KEY,
    blob            BLOB    NOT NULL,
    stored_at       REAL    NOT NULL,
    entry_hash      TEXT    NOT NULL DEFAULT '',
    rekor_entry_ref TEXT    NOT NULL DEFAULT '',
    tier            TEXT    NOT NULL DEFAULT 'operational',
    locked          INTEGER NOT NULL DEFAULT 0,
    created_at      REAL    NOT NULL
);
"""

_CREATE_IDX_STORED_AT = """
CREATE INDEX IF NOT EXISTS idx_receipts_stored_at
    ON receipts(stored_at);
"""

_CREATE_IDX_TIER = """
CREATE INDEX IF NOT EXISTS idx_receipts_tier
    ON receipts(tier, locked);
"""

_CREATE_AMBIENT = """
CREATE TABLE IF NOT EXISTS ambient_receipts (
    snapshot_id TEXT    NOT NULL PRIMARY KEY,
    blob        BLOB    NOT NULL,
    stored_at   REAL    NOT NULL,
    session_id  TEXT    NOT NULL,
    trigger     TEXT    NOT NULL,
    tier        TEXT    NOT NULL DEFAULT 'operational'
);
"""

_CREATE_IDX_AMBIENT = """
CREATE INDEX IF NOT EXISTS idx_ambient_session
    ON ambient_receipts(session_id, stored_at);
"""


class SqliteReceiptStore:
    """
    Three-tier receipt store backed by SQLite WAL.

    db_path=":memory:" is dev/test mode — all data is process-local and lost
    when the store is closed. AEVUM_DEV=1 sets this automatically via from_env().
    """

    def __init__(self, db_path: str | None = None) -> None:
        import os
        self._db_path = db_path or os.environ.get("AEVUM_RECEIPT_DB", ":memory:")
        self._conn = self._connect()
        self._create_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _create_schema(self) -> None:
        self._conn.executescript(
            _CREATE_RECEIPTS
            + _CREATE_IDX_STORED_AT
            + _CREATE_IDX_TIER
            + _CREATE_AMBIENT
            + _CREATE_IDX_AMBIENT
        )
        self._conn.commit()

    # ── Receipt CRUD ──────────────────────────────────────────────────────────

    def put(
        self,
        receipt_hash: str,
        blob: bytes,
        entry_hash: str = "",
        rekor_entry_ref: str = "",
        tier: str = "operational",
    ) -> None:
        """Store a receipt. Idempotent — storing the same hash twice is a no-op."""
        now = time.time()
        self._conn.execute(
            """
            INSERT OR IGNORE INTO receipts
                (receipt_hash, blob, stored_at, entry_hash, rekor_entry_ref, tier, locked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (receipt_hash, blob, now, entry_hash, rekor_entry_ref, tier, now),
        )
        self._conn.commit()

    def get(self, receipt_hash: str) -> bytes | None:
        row = self._conn.execute(
            "SELECT blob FROM receipts WHERE receipt_hash = ?",
            (receipt_hash,),
        ).fetchone()
        return bytes(row[0]) if row is not None else None

    def lock(self, receipt_hash: str) -> None:
        """
        Escalate a receipt to crash_protected tier.
        Idempotent — locking an already-locked receipt is safe.
        Raises ReceiptNotFoundError if receipt_hash does not exist.
        There is no unlock() — crash_protected escalation is permanent.
        """
        row = self._conn.execute(
            "SELECT 1 FROM receipts WHERE receipt_hash = ?",
            (receipt_hash,),
        ).fetchone()
        if row is None:
            raise ReceiptNotFoundError(
                f"receipt_hash not found: {receipt_hash!r}"
            )
        self._conn.execute(
            "UPDATE receipts SET locked = 1, tier = 'crash_protected' WHERE receipt_hash = ?",
            (receipt_hash,),
        )
        self._conn.commit()

    def list_hashes(
        self,
        after: str | None = None,
        limit: int = 100,
        tier: str | None = None,
    ) -> list[str]:
        """
        Return receipt_hashes in lexicographic order.
        after: keyset pagination cursor — returns hashes > after.
        tier: filter by tier; None returns all tiers.
        """
        # Use explicit query branches to avoid f-string SQL (bandit B608).
        if after is not None and tier is not None:
            sql = (
                "SELECT receipt_hash FROM receipts"
                " WHERE receipt_hash > ? AND tier = ?"
                " ORDER BY receipt_hash LIMIT ?"
            )
            rows = self._conn.execute(sql, [after, tier, limit]).fetchall()
        elif after is not None:
            sql = (
                "SELECT receipt_hash FROM receipts"
                " WHERE receipt_hash > ?"
                " ORDER BY receipt_hash LIMIT ?"
            )
            rows = self._conn.execute(sql, [after, limit]).fetchall()
        elif tier is not None:
            sql = (
                "SELECT receipt_hash FROM receipts"
                " WHERE tier = ?"
                " ORDER BY receipt_hash LIMIT ?"
            )
            rows = self._conn.execute(sql, [tier, limit]).fetchall()
        else:
            sql = "SELECT receipt_hash FROM receipts ORDER BY receipt_hash LIMIT ?"
            rows = self._conn.execute(sql, [limit]).fetchall()
        return [r[0] for r in rows]

    # ── Ambient receipts ──────────────────────────────────────────────────────

    def put_ambient(
        self,
        snapshot_id: str,
        blob: bytes,
        session_id: str,
        trigger: str,
    ) -> None:
        """Store an ambient context receipt. Idempotent on snapshot_id."""
        now = time.time()
        self._conn.execute(
            """
            INSERT OR IGNORE INTO ambient_receipts
                (snapshot_id, blob, stored_at, session_id, trigger, tier)
            VALUES (?, ?, ?, ?, ?, 'operational')
            """,
            (snapshot_id, blob, now, session_id, trigger),
        )
        self._conn.commit()

    def get_ambient(self, snapshot_id: str) -> bytes | None:
        row = self._conn.execute(
            "SELECT blob FROM ambient_receipts WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        return bytes(row[0]) if row is not None else None

    # ── Maintenance ───────────────────────────────────────────────────────────

    def rotate_operational(self, hours: int = 48) -> int:
        """
        Promote operational receipts older than `hours` to long_term tier.
        Does NOT delete — long_term is the EU AI Act Art. 26(6) minimum (6 months).

        This method must be called on a schedule to prevent unbounded growth of
        the operational tier. Recommended frequency: daily.

        Returns the number of receipts promoted.
        """
        cutoff = time.time() - hours * 3600
        cur = self._conn.execute(
            """
            UPDATE receipts
            SET tier = 'long_term'
            WHERE tier = 'operational'
              AND locked = 0
              AND stored_at < ?
            """,
            (cutoff,),
        )
        self._conn.commit()
        return cur.rowcount

    # ── Store info ────────────────────────────────────────────────────────────

    def get_receipt_info(self, receipt_hash: str) -> dict[str, object] | None:
        """Return tier/locked metadata for a receipt, or None if not found."""
        row = self._conn.execute(
            "SELECT tier, locked, rekor_entry_ref FROM receipts WHERE receipt_hash = ?",
            (receipt_hash,),
        ).fetchone()
        if row is None:
            return None
        return {
            "tier": row[0],
            "locked": bool(row[1]),
            "rekor_entry_ref": row[2],
        }

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> SqliteReceiptStore:
        """
        Construct from environment variables.
        AEVUM_DEV=1  → :memory: (process-local, lost on close)
        AEVUM_RECEIPT_DB → path to the SQLite file
        Raises RuntimeError if AEVUM_RECEIPT_DB is unset in non-dev mode.
        """
        import os
        if os.environ.get("AEVUM_DEV") == "1":
            return cls(db_path=":memory:")
        db_path = os.environ.get("AEVUM_RECEIPT_DB")
        if not db_path:
            raise RuntimeError(
                "AEVUM_RECEIPT_DB environment variable is not set. "
                "Set it to a file path for the SQLite receipt store, "
                "or set AEVUM_DEV=1 for in-memory mode."
            )
        return cls(db_path=db_path)
