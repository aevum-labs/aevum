"""
PostgresConsentLedger — ConsentLedgerProtocol backed by PostgreSQL.

Grants stored as JSONB in aevum_consent_grants.
OR-Set semantics: revocation wins over concurrent grants.
Expiration checked in Python (matching InMemoryConsentLedger behaviour).
"""

from __future__ import annotations

import contextlib
import json
import threading
from datetime import UTC, datetime
from typing import Any

from aevum.core.consent.models import ConsentGrant


class PostgresConsentLedger:
    """
    ConsentLedgerProtocol implementation backed by PostgreSQL.

    Args:
        conn:  An open psycopg.Connection (autocommit=True recommended).
        lock:  Optional shared Lock. Pass the same lock used by PostgresStore
               when both share one connection.
    """

    def __init__(self, conn: Any, lock: threading.Lock | None = None) -> None:
        self._conn = conn
        self._lock = lock or threading.Lock()

    # ── ConsentLedgerProtocol ──────────────────────────────────────────────────

    def add_grant(self, grant: ConsentGrant) -> None:
        """Upsert a consent grant. Replaces any prior record with the same grant_id."""
        sql = """
            INSERT INTO aevum_consent_grants (grant_id, grant_data)
            VALUES (%s, %s::jsonb)
            ON CONFLICT (grant_id) DO UPDATE SET grant_data = EXCLUDED.grant_data
        """
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (grant.grant_id, json.dumps(grant.model_dump())))

    def revoke_grant(self, grant_id: str) -> None:
        """Mark a grant as revoked (immutable update via JSONB merge)."""
        sql = """
            UPDATE aevum_consent_grants
            SET grant_data = jsonb_set(grant_data, '{revocation_status}', '"revoked"')
            WHERE grant_id = %s
        """
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (grant_id,))

    def has_consent(
        self,
        *,
        subject_id: str,
        operation: str,
        grantee_id: str,
        purpose: str | None = None,
    ) -> bool:
        """
        Return True if an active, unexpired grant covers this operation.

        Mirrors InMemoryConsentLedger: loads candidates from DB, checks
        expiration and operation in Python to stay consistent with the spec.
        """
        sql = """
            SELECT grant_data
            FROM aevum_consent_grants
            WHERE grant_data->>'subject_id'       = %s
              AND grant_data->>'grantee_id'        = %s
              AND grant_data->>'revocation_status' = 'active'
        """
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (subject_id, grantee_id))
            rows = cur.fetchall()

        now = datetime.now(UTC)
        for row in rows:
            raw = row[0]
            d: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else raw
            if operation not in d.get("operations", []):
                continue
            try:
                expires = datetime.fromisoformat(
                    d["expires_at"].replace("Z", "+00:00")
                )
                if now > expires:
                    continue
            except (KeyError, ValueError):
                continue
            return True
        return False

    def all_grants(self) -> list[ConsentGrant]:
        """Return all stored grants (active, revoked, and expired)."""
        sql = "SELECT grant_data FROM aevum_consent_grants"
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        grants: list[ConsentGrant] = []
        for row in rows:
            raw = row[0]
            d: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else raw
            with contextlib.suppress(Exception):
                grants.append(ConsentGrant(**d))
        return grants
