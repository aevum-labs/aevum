"""
Test fixtures for aevum-store-postgres.

Integration tests (requiring a real DB) use pg_conn / pg_store / pg_consent
fixtures, which skip if AEVUM_TEST_POSTGRES_DSN is not set.

Unit tests use fake_store_parts — an in-memory FakeConn that stores data in
plain dicts so behaviour can be verified without a real database.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

import pytest


POSTGRES_DSN = os.environ.get("AEVUM_TEST_POSTGRES_DSN", "")


# ── FakeConn: in-memory psycopg3 stub ────────────────────────────────────────

class _FakeCursor:
    """Minimal cursor stub backed by in-memory dicts."""

    def __init__(self, store: dict[str, Any]) -> None:
        self._store = store
        self._rows: list[Any] = []

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] = ()) -> None:
        sql_up = " ".join(sql.split()).upper()

        # --- aevum_entities ---
        if "INSERT INTO AEVUM_ENTITIES" in sql_up:
            entity_id, data_raw, classification = params[0], params[1], params[2]
            data = json.loads(data_raw) if isinstance(data_raw, str) else data_raw
            self._store["entities"][entity_id] = {
                "data": data, "classification": int(classification)
            }

        elif sql_up.startswith("SELECT DATA FROM AEVUM_ENTITIES"):
            entity_id = params[0]
            row = self._store["entities"].get(entity_id)
            self._rows = [(row["data"],)] if row else []

        elif "SELECT ENTITY_ID, DATA" in sql_up:
            ids, cls_max = list(params[0]), int(params[1])
            self._rows = [
                (eid, rec["data"])
                for eid, rec in self._store["entities"].items()
                if eid in ids and rec["classification"] <= cls_max
            ]

        elif "SELECT CLASSIFICATION FROM AEVUM_ENTITIES" in sql_up:
            entity_id = params[0]
            row = self._store["entities"].get(entity_id)
            self._rows = [(row["classification"],)] if row else []

        elif "SELECT COUNT(*) FROM AEVUM_ENTITIES" in sql_up:
            self._rows = [(len(self._store["entities"]),)]

        # --- aevum_consent_grants ---
        elif "INSERT INTO AEVUM_CONSENT_GRANTS" in sql_up:
            grant_id, grant_raw = params[0], params[1]
            d = json.loads(grant_raw) if isinstance(grant_raw, str) else grant_raw
            self._store["grants"][grant_id] = d

        elif "UPDATE AEVUM_CONSENT_GRANTS" in sql_up and "REVOKED" in sql_up:
            grant_id = params[0]
            if grant_id in self._store["grants"]:
                self._store["grants"][grant_id]["revocation_status"] = "revoked"

        elif "SELECT GRANT_DATA" in sql_up and "WHERE" in sql_up:
            subject_id, grantee_id = params[0], params[1]
            self._rows = [
                (d,)
                for d in self._store["grants"].values()
                if d.get("subject_id") == subject_id
                and d.get("grantee_id") == grantee_id
                and d.get("revocation_status") == "active"
            ]

        elif "SELECT GRANT_DATA FROM AEVUM_CONSENT_GRANTS" in sql_up:
            self._rows = [(d,) for d in self._store["grants"].values()]

        elif "CREATE TABLE" in sql_up or "DELETE FROM" in sql_up:
            pass  # DDL / cleanup — no-op in fake

    def fetchone(self) -> Any | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class FakeConn:
    """In-memory fake psycopg3 connection for unit tests (no real DB)."""

    def __init__(self) -> None:
        self._store: dict[str, Any] = {"entities": {}, "grants": {}}

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._store)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


# ── Pytest fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def fake_store_parts():
    """Return (PostgresStore, PostgresConsentLedger, Lock) backed by FakeConn."""
    from aevum.store.postgres import PostgresConsentLedger, PostgresStore
    conn = FakeConn()
    lock = threading.Lock()
    return PostgresStore(conn, lock), PostgresConsentLedger(conn, lock), lock


@pytest.fixture
def pg_conn():
    """Open psycopg3 connection to a real Postgres instance."""
    if not POSTGRES_DSN:
        pytest.skip("requires AEVUM_TEST_POSTGRES_DSN env var")
    import psycopg  # type: ignore[import]
    conn = psycopg.connect(POSTGRES_DSN, autocommit=True)
    from aevum.store.postgres.schema import initialize_schema
    initialize_schema(conn)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM aevum_entities")
        cur.execute("DELETE FROM aevum_consent_grants")
    yield conn
    conn.close()


@pytest.fixture
def pg_lock() -> threading.Lock:
    return threading.Lock()


@pytest.fixture
def pg_store(pg_conn: Any, pg_lock: threading.Lock):
    from aevum.store.postgres import PostgresStore
    return PostgresStore(pg_conn, pg_lock)


@pytest.fixture
def pg_consent(pg_conn: Any, pg_lock: threading.Lock):
    from aevum.store.postgres import PostgresConsentLedger
    return PostgresConsentLedger(pg_conn, pg_lock)
