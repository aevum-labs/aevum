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
                    self.description = [[k] for k in last_row.keys()]
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

@pytest.mark.skipif(not _POSTGRES_DSN, reason="Requires AEVUM_TEST_POSTGRES_DSN")
class TestPostgresLedgerIntegration:
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
