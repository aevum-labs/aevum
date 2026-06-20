# SPDX-License-Identifier: Apache-2.0
"""
Tests for PostgresLedger.
Uses FakeConn (no real database). Integration tests skip without AEVUM_TEST_POSTGRES_DSN.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import os

import pytest
from aevum.core.audit.sigchain import Sigchain
from aevum.core.exceptions import BarrierViolationError, ReplayNotFoundError

from aevum.store.postgres.ledger import PostgresLedger, _event_to_row


class FakeConn:
    """Minimal psycopg3-compatible connection for unit tests."""

    def __init__(self) -> None:
        self._rows: list[dict] = []
        self._sequence = 0

    def cursor(self, row_factory=None):
        return FakeCursor(self, row_factory)

    def commit(self) -> None:
        pass


class FakeCursor:
    def __init__(self, conn: FakeConn, row_factory=None) -> None:
        self._conn = conn
        self._row_factory = row_factory
        self._last_result: list = []
        self.description: list = []

    def __enter__(self): return self
    def __exit__(self, *args): pass

    def execute(self, sql: str, params=None) -> None:
        sql_lower = sql.lower().strip()
        if sql_lower.startswith("insert"):
            if params:
                self._conn._sequence += 1
                row = dict(params) if isinstance(params, dict) else {}
                row["sequence"] = self._conn._sequence
                self._conn._rows.append(row)
        elif "count(*)" in sql_lower:
            self._last_result = [(len(self._conn._rows),)]
            self.description = [("count",)]
        elif "where audit_id" in sql_lower:
            audit_id = params[0] if params else None
            matches = [r for r in self._conn._rows if r.get("audit_id") == audit_id]
            self._last_result = [list(r.values()) for r in matches]
            self.description = [[k] for k in (matches[0].keys() if matches else [])]
        elif "order by sequence desc" in sql_lower and "limit 1" in sql_lower:
            if self._conn._rows:
                last_row = max(self._conn._rows, key=lambda r: r.get("sequence", 0))
                if "select audit_id" in sql_lower:
                    self._last_result = [[last_row.get("audit_id", "")]]
                    self.description = [["audit_id"]]
                else:
                    self._last_result = [list(last_row.values())]
                    self.description = [[k] for k in last_row]
            else:
                self._last_result = []
                self.description = []
        elif "order by sequence" in sql_lower:
            sorted_rows = sorted(self._conn._rows, key=lambda r: r.get("sequence", 0))
            self._last_result = [list(r.values()) for r in sorted_rows]
            self.description = [[k] for k in (sorted_rows[0].keys() if sorted_rows else [])]

    def fetchone(self):
        if not self._last_result:
            return None
        if self._row_factory:
            return dict(zip([d[0] for d in self.description], self._last_result[0], strict=False))
        return self._last_result[0]

    def fetchall(self):
        if self._row_factory:
            return [
                dict(zip([d[0] for d in self.description], row, strict=False))
                for row in self._last_result
            ]
        return self._last_result


class TestPostgresLedger:
    def _ledger(self) -> tuple[PostgresLedger, FakeConn]:
        conn = FakeConn()
        sigchain = Sigchain()
        return PostgresLedger(conn, sigchain), conn

    def test_append_returns_event(self) -> None:
        ledger, _ = self._ledger()
        event = ledger.append(event_type="test.event", payload={"k": "v"}, actor="actor")
        assert event.event_type == "test.event"
        assert event.actor == "actor"
        assert event.audit_id().startswith("urn:aevum:audit:")

    def test_count_increments(self) -> None:
        ledger, _ = self._ledger()
        assert ledger.count() == 0
        ledger.append(event_type="test.e", payload={}, actor="a")
        assert ledger.count() == 1

    def test_barrier4_delete_raises(self) -> None:
        ledger, _ = self._ledger()
        with pytest.raises(BarrierViolationError):
            del ledger["any"]

    def test_barrier4_setitem_raises(self) -> None:
        ledger, _ = self._ledger()
        with pytest.raises(BarrierViolationError):
            ledger["k"] = "v"  # type: ignore[index]

    def test_satisfies_protocol(self) -> None:
        from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
        ledger, _ = self._ledger()
        assert isinstance(ledger, AuditLedgerProtocol)

    def test_event_row_round_trip(self) -> None:
        sigchain = Sigchain()
        event = sigchain.new_event(event_type="test.rt", payload={"x": 1}, actor="a")
        row = _event_to_row(event)
        assert row["event_type"] == "test.rt"
        assert row["actor"] == "a"
        assert "payload" in row


def test_rollback_on_write_failure() -> None:
    """Failed INSERT must not corrupt in-memory sigchain state."""
    from aevum.core.audit.sigchain import GENESIS_HASH

    class ExplodingCursor:
        description: list = []
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, sql: str, params=None) -> None:
            if "INSERT" in sql.upper():
                raise RuntimeError("simulated disk full")
        def fetchone(self): return None
        def fetchall(self): return []

    class ExplodingConn:
        _rows: list = []
        _sequence: int = 0
        def cursor(self, row_factory=None): return ExplodingCursor()
        def commit(self): pass

    sc = Sigchain()
    ledger = PostgresLedger(ExplodingConn(), sc)

    with pytest.raises(RuntimeError):
        ledger.append(event_type="will.fail", payload={}, actor="a")

    assert sc._sequence == 0, f"rollback failed: _sequence={sc._sequence}"
    assert sc._prior_hash == GENESIS_HASH, "rollback failed: prior_hash changed"


def test_chain_continuity_across_restart() -> None:
    """New PostgresLedger on existing data must continue the chain."""
    conn = FakeConn()
    sc1 = Sigchain()
    ledger1 = PostgresLedger(conn, sc1)
    for i in range(3):
        ledger1.append(event_type=f"s1.{i}", payload={"i": i}, actor="a")
    assert sc1._sequence == 3

    # Simulate restart: new sigchain + new ledger on same conn
    sc2 = Sigchain()
    assert sc2._sequence == 0  # starts fresh

    ledger2 = PostgresLedger(conn, sc2)  # _resume_chain_from_db fires

    assert sc2._sequence == 3, (
        f"Expected sequence=3 after resume, got {sc2._sequence}. "
        "Chain fork: each restart should CONTINUE, not start over."
    )

    e = ledger2.append(event_type="s2.first", payload={}, actor="b")
    assert e.sequence == 4, f"Expected sequence=4, got {e.sequence}"


def test_last_audit_id_empty() -> None:
    conn = FakeConn()
    ledger = PostgresLedger(conn, Sigchain())
    assert ledger.last_audit_id() is None


def test_last_audit_id_after_append() -> None:
    conn = FakeConn()
    ledger = PostgresLedger(conn, Sigchain())
    e = ledger.append(event_type="test", payload={}, actor="a")
    assert ledger.last_audit_id() == e.audit_id()


# Integration tests -- require a real Postgres database
_POSTGRES_DSN = os.environ.get("AEVUM_TEST_POSTGRES_DSN")

# Pre-HO-G-PG2 schema: every column aevum_ledger had BEFORE
# _DDL_MIGRATE_SIGNED_FIELDS (sig_format_version, key_scheme, hash_alg,
# mldsa65_*, tsa_*, receipt_cbor, principal_*) was added. Used by
# test_pg2_migration_on_populated_table_then_v2_round_trip (HO-SESSION5-CLOSE
# / PG3) to simulate a real pre-migration deployment rather than a fresh table.
_OLD_SCHEMA_DDL = """
CREATE TABLE aevum_ledger (
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
"""

_OLD_SCHEMA_COLUMNS = (
    "event_id", "audit_id", "event_type", "actor", "system_time",
    "episode_id", "causation_id", "correlation_id",
    "prior_hash", "payload_hash", "signature", "signer_key_id",
    "schema_version", "valid_from", "valid_to",
    "trace_id", "span_id", "payload",
)

_INSERT_OLD_SCHEMA_ROW_SQL = """
INSERT INTO aevum_ledger (
    event_id, audit_id, event_type, actor, system_time,
    episode_id, causation_id, correlation_id,
    prior_hash, payload_hash, signature, signer_key_id,
    schema_version, valid_from, valid_to,
    trace_id, span_id, payload
) VALUES (
    %(event_id)s, %(audit_id)s, %(event_type)s, %(actor)s, %(system_time)s,
    %(episode_id)s, %(causation_id)s, %(correlation_id)s,
    %(prior_hash)s, %(payload_hash)s, %(signature)s, %(signer_key_id)s,
    %(schema_version)s, %(valid_from)s, %(valid_to)s,
    %(trace_id)s, %(span_id)s, %(payload)s::jsonb
)
"""


@pytest.mark.skipif(not _POSTGRES_DSN, reason="Requires AEVUM_TEST_POSTGRES_DSN")
class TestPostgresLedgerIntegration:
    @pytest.fixture(autouse=True)
    def _reset_ledger_table(self) -> None:
        """
        Drop aevum_ledger before every test in this class.

        Each test manages its own schema/rows and ends by chain-verifying
        whatever it finds via all_events(). Without a hard reset, rows left
        behind by an earlier test (signed by THAT test's own Sigchain key)
        would be picked up by a later test's verify_chain() call and fail
        signature verification against a different key -- a false failure,
        not a real chain defect.
        """
        import psycopg

        conn = psycopg.connect(_POSTGRES_DSN)
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS aevum_ledger CASCADE;")
        conn.commit()
        conn.close()

    def _real_ledger(self) -> PostgresLedger:
        import psycopg

        from aevum.store.postgres.ledger import initialize_ledger_schema
        conn = psycopg.connect(_POSTGRES_DSN)
        initialize_ledger_schema(conn)
        sigchain = Sigchain()
        return PostgresLedger(conn, sigchain)

    def test_append_and_get(self) -> None:
        ledger = self._real_ledger()
        event = ledger.append(event_type="integ.test", payload={"k": "v"}, actor="a")
        retrieved = ledger.get(event.audit_id())
        assert retrieved.event_type == "integ.test"

    def test_get_not_found(self) -> None:
        ledger = self._real_ledger()
        with pytest.raises(ReplayNotFoundError):
            ledger.get("urn:aevum:audit:00000000-0000-7000-8000-000000000999")

    def test_sigchain_survives_restart(self) -> None:
        """Sigchain verification works after reading from Postgres."""
        import psycopg

        from aevum.store.postgres.ledger import initialize_ledger_schema
        conn = psycopg.connect(_POSTGRES_DSN)
        initialize_ledger_schema(conn)
        sigchain = Sigchain()
        ledger = PostgresLedger(conn, sigchain)
        for i in range(5):
            ledger.append(event_type=f"t.{i}", payload={"i": i}, actor="a")
        events = ledger.all_events()
        assert sigchain.verify_chain(events) is True

    def test_pg2_migration_on_populated_table_then_v2_round_trip(self) -> None:
        """
        HO-SESSION5-CLOSE / PG3: the HO-G-PG2 migration (_DDL_MIGRATE_SIGNED_FIELDS)
        was previously only exercised against FakeConn. This proves it against a
        real server, on a table that already holds real signed rows -- not an
        empty one -- then proves the chain resumes across the migration boundary
        and a new v2 (commitment_key_id) entry round-trips through Postgres and
        verifies end to end alongside the pre-migration rows.
        """
        import psycopg
        from aevum.core.audit.commitment_key_store import CommitmentKeyStore

        from aevum.store.postgres.ledger import _DDL_MIGRATE_SIGNED_FIELDS, _event_to_row

        conn = psycopg.connect(_POSTGRES_DSN)

        # 1. Create the OLD (pre-HO-G-PG2) schema -- as a real deployment that
        # predates this migration would have.
        with conn.cursor() as cur:
            cur.execute(_OLD_SCHEMA_DDL)
        conn.commit()

        # Confirm the new columns are genuinely absent (not just no-opped by
        # IF NOT EXISTS because they happened to already be there).
        with pytest.raises(Exception), conn.cursor() as cur:  # noqa: B017 -- psycopg.errors.UndefinedColumn
            cur.execute("SELECT sig_format_version FROM aevum_ledger LIMIT 1")
        conn.rollback()

        # 2. Populate it with real, signed v1 rows -- as a pre-migration
        # deployment would have written them.
        sigchain = Sigchain()
        pre_migration_events = [
            sigchain.new_event(event_type=f"pre.{i}", payload={"i": i}, actor="legacy")
            for i in range(5)
        ]
        with conn.cursor() as cur:
            for event in pre_migration_events:
                row = _event_to_row(event)
                cur.execute(_INSERT_OLD_SCHEMA_ROW_SQL, {c: row[c] for c in _OLD_SCHEMA_COLUMNS})
        conn.commit()

        # 3. Run the actual HO-G-PG2 migration against the now-populated table.
        with conn.cursor() as cur:
            cur.execute(_DDL_MIGRATE_SIGNED_FIELDS)
        conn.commit()

        # 4. Pre-existing rows must be correctly backfilled: mandatory-default
        # columns get their single historical value, genuinely-absent columns
        # stay NULL (see comment above _DDL_MIGRATE_SIGNED_FIELDS).
        with conn.cursor() as cur:
            cur.execute(
                "SELECT sig_format_version, key_scheme, hash_alg, mldsa65_sig, "
                "tsa_token, principal_commitment_key_id FROM aevum_ledger ORDER BY sequence"
            )
            rows = cur.fetchall()
        assert len(rows) == 5
        for sfv, ks, ha, mldsa_sig, tsa_token, commitment_key_id in rows:
            assert (sfv, ks, ha, mldsa_sig, tsa_token, commitment_key_id) == (
                1, "ed25519", "sha3-256", None, None, None,
            )

        # 5. Simulate a process restart on the now-migrated table: reload the
        # SAME signing key (a real deployment persists and reloads its key
        # the same way) and let _resume_chain_from_db continue the chain,
        # then append a NEW v2 (commitment_key_id) entry.
        # _private_key is InProcessSigner-only; Sigchain() always wraps in InProcessSigner here.
        sigchain2 = Sigchain(
            private_key=sigchain._signer._private_key,  # type: ignore[attr-defined]
            key_id=sigchain.key_id,
        )
        key_store = CommitmentKeyStore()
        key_id = key_store.create_key(scope="pg3-integration-test")
        ledger = PostgresLedger(conn, sigchain2, commitment_key_store=key_store)
        assert sigchain2._sequence == 5, "chain must resume across the migration boundary"

        v2_event = ledger.append(
            event_type="post.migration.v2",
            payload={"after": "migration"},
            actor="current",
            principal_identity="urn:oidc:sub:pg3-test-principal",
            principal_claims={"email": "pg3@example.test"},
            commitment_key_id=key_id,
        )
        assert v2_event.sig_format_version == 2
        assert v2_event.principal_commitment_key_id == key_id

        # 6. The full chain -- pre-migration v1 rows AND the new v2 row --
        # must round-trip through Postgres and verify end to end.
        all_events = ledger.all_events()
        assert len(all_events) == 6
        assert sigchain2.verify_chain(all_events) is True
