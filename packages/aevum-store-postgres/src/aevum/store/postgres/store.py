"""
PostgresStore — GraphStore Protocol backed by PostgreSQL via psycopg3 (sync).

Satisfies aevum.core.protocols.graph_store.GraphStore.
Uses two tables defined in schema.py.

Classification ceiling (Barrier 2) is enforced at query_entities().
Thread-safe via shared threading.Lock (same lock used by PostgresConsentLedger
when both share one connection).
"""

from __future__ import annotations

import json
import threading
from typing import Any


class PostgresStore:
    """
    GraphStore implementation backed by PostgreSQL.

    Args:
        conn:  An open psycopg.Connection (autocommit=True recommended).
        lock:  Optional shared Lock. If both PostgresStore and
               PostgresConsentLedger share one connection, pass the same lock
               to serialise access.
    """

    def __init__(self, conn: Any, lock: threading.Lock | None = None) -> None:
        self._conn = conn
        self._lock = lock or threading.Lock()

    # ── GraphStore Protocol ────────────────────────────────────────────────────

    def store_entity(
        self,
        entity_id: str,
        data: dict[str, Any],
        classification: int = 0,
    ) -> None:
        """Upsert an entity. Last write wins (update semantics)."""
        sql = """
            INSERT INTO aevum_entities (entity_id, data, classification)
            VALUES (%s, %s::jsonb, %s)
            ON CONFLICT (entity_id) DO UPDATE
              SET data           = EXCLUDED.data,
                  classification = EXCLUDED.classification,
                  ingested_at    = NOW()
        """
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (entity_id, json.dumps(data), classification))

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        """Return entity data dict, or None if not found."""
        sql = "SELECT data FROM aevum_entities WHERE entity_id = %s"
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (entity_id,))
            row = cur.fetchone()
        if row is None:
            return None
        raw = row[0]
        result: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else raw
        return result

    def query_entities(
        self,
        subject_ids: list[str],
        classification_max: int = 0,
    ) -> dict[str, dict[str, Any]]:
        """
        Return entities for the given subject IDs.
        Excludes entities whose classification exceeds classification_max (Barrier 2).
        """
        if not subject_ids:
            return {}
        sql = """
            SELECT entity_id, data
            FROM aevum_entities
            WHERE entity_id = ANY(%s)
              AND classification <= %s
        """
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (subject_ids, classification_max))
            rows = cur.fetchall()
        result: dict[str, dict[str, Any]] = {}
        for entity_id, raw in rows:
            data = json.loads(raw) if isinstance(raw, str) else raw
            result[entity_id] = data
        return result

    # ── Extra helpers (not in protocol — used by migrate) ─────────────────────

    def get_entity_classification(self, entity_id: str) -> int:
        """Return classification level of an entity (default 0 if not found)."""
        sql = "SELECT classification FROM aevum_entities WHERE entity_id = %s"
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, (entity_id,))
            row = cur.fetchone()
        if row is None:
            return 0
        return int(row[0])

    def entity_count(self) -> int:
        """Return total number of stored entities."""
        sql = "SELECT COUNT(*) FROM aevum_entities"
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql)
            row = cur.fetchone()
        return int(row[0]) if row else 0
