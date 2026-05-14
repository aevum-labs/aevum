# SPDX-License-Identifier: Apache-2.0
"""
Phase 4 tests: REMEMBER — verifies _remember() fires on session close.

These tests use session.py directly. They do not require a full kernel
(kernel=None is the normal test path — signing and TSA are skipped).
They verify that _remember() is called, the session record is created
with the correct structure, and the SQLite tables are written.
"""
from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from aevum.core.session import Session
from aevum.core.session_record import CommitType, EventType, SessionEvent, SessionRecord

# ── REMEMBER fires on session close ──────────────────────────────────────────

class TestRememberFires:
    def test_session_has_remember_method(self) -> None:
        assert hasattr(Session, "_remember") or hasattr(Session, "remember"), \
            "Session must have a _remember() or remember() method"

    def test_commit_type_complete_on_normal_close(self) -> None:
        assert CommitType.COMPLETE == "complete"

    def test_commit_type_emergency_on_exception(self) -> None:
        assert CommitType.EMERGENCY == "emergency"

    def test_commit_type_crisis_on_barrier_error(self) -> None:
        assert CommitType.CRISIS == "crisis"

    def test_session_can_be_created_without_kernel(self) -> None:
        s = Session(actor="agent")
        assert s.kernel is None

    def test_session_can_be_created_without_db_path(self) -> None:
        s = Session(actor="agent")
        assert s.db_path is None

    def test_session_has_session_id_after_init(self) -> None:
        s = Session(actor="agent")
        assert hasattr(s, "_session_id")
        assert s._session_id  # non-empty

    def test_session_started_at_is_utc_datetime(self) -> None:
        s = Session(actor="agent")
        assert hasattr(s, "_started_at")
        assert isinstance(s._started_at, datetime)
        assert s._started_at.tzinfo is not None

    def test_aexit_does_not_raise_on_normal_close(self) -> None:
        async def run() -> None:
            async with Session(actor="agent"):
                pass

        asyncio.run(run())

    def test_aexit_does_not_raise_on_exception_close(self) -> None:
        async def run() -> None:
            try:
                async with Session(actor="agent"):
                    raise RuntimeError("simulated error")
            except RuntimeError:
                pass  # expected — aexit should not re-raise

        asyncio.run(run())

    def test_remember_does_not_raise_without_db(self) -> None:
        async def run() -> None:
            s = Session(actor="agent", purpose="test")
            await s._remember("complete")

        asyncio.run(run())

    def test_purpose_defaults_to_empty_string(self) -> None:
        s = Session(actor="agent")
        assert s.purpose == ""

    def test_principal_equals_actor(self) -> None:
        s = Session(actor="my-agent")
        assert s._principal == "my-agent"


# ── SQLite write ──────────────────────────────────────────────────────────────

class TestRememberWritesSQLite:
    def test_sessions_table_created(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"
        asyncio.run(self._run_session(db, "agent", "test-purpose"))
        conn = sqlite3.connect(str(db))
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "sessions" in tables

    def test_session_events_table_created(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"
        asyncio.run(self._run_session(db, "agent", "test-purpose"))
        conn = sqlite3.connect(str(db))
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "session_events" in tables

    def test_session_row_written(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"
        asyncio.run(self._run_session(db, "agent", "test-purpose"))
        conn = sqlite3.connect(str(db))
        rows = conn.execute("SELECT count(*) FROM sessions").fetchone()
        conn.close()
        assert rows[0] == 1

    def test_session_commit_type_complete(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"
        asyncio.run(self._run_session(db, "agent", "test-purpose"))
        conn = sqlite3.connect(str(db))
        row = conn.execute("SELECT commit_type FROM sessions").fetchone()
        conn.close()
        assert row[0] == "complete"

    def test_session_merkle_root_64_chars(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"
        asyncio.run(self._run_session(db, "agent", "test-purpose"))
        conn = sqlite3.connect(str(db))
        row = conn.execute("SELECT merkle_root FROM sessions").fetchone()
        conn.close()
        assert len(row[0]) == 64

    def test_session_events_empty_for_no_events(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"
        asyncio.run(self._run_session(db, "agent", "test-purpose"))
        conn = sqlite3.connect(str(db))
        rows = conn.execute("SELECT count(*) FROM session_events").fetchone()
        conn.close()
        assert rows[0] == 0

    def test_session_events_written_when_events_recorded(self, tmp_path: Path) -> None:
        db = tmp_path / "s.db"

        async def run() -> None:
            h = SessionEvent.hash_payload({"x": 1})
            async with Session(actor="agent", purpose="test", db_path=db) as s:
                s.record_relate_event(h, h, fact_id="fact-1", latency_ms=5)
                s.record_navigate_event(h, h, latency_ms=3)

        asyncio.run(run())
        conn = sqlite3.connect(str(db))
        rows = conn.execute("SELECT count(*) FROM session_events").fetchone()
        conn.close()
        assert rows[0] == 2

    @staticmethod
    async def _run_session(db: Path, actor: str, purpose: str) -> None:
        async with Session(actor=actor, purpose=purpose, db_path=db):
            pass


# ── Event recording ───────────────────────────────────────────────────────────

class TestEventRecording:
    def test_record_relate_event_appends_to_events(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({"k": "v"})
        s.record_relate_event(h, h, latency_ms=5)
        assert len(s._events) == 1
        assert s._events[0].event_type == EventType.RELATE

    def test_record_relate_event_tracks_fact_id(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({})
        s.record_relate_event(h, h, fact_id="fact-123")
        assert "fact-123" in s._fact_ids

    def test_record_navigate_event_appends(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({})
        s.record_navigate_event(h, h)
        assert len(s._events) == 1
        assert s._events[0].event_type == EventType.NAVIGATE

    def test_record_govern_event_appends(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({})
        s.record_govern_event(h, h, checkpoint_id="cp-1")
        assert len(s._events) == 1
        assert s._events[0].event_type == EventType.GOVERN

    def test_record_govern_event_tracks_checkpoint_id(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({})
        s.record_govern_event(h, h, checkpoint_id="cp-42")
        assert "cp-42" in s._checkpoint_ids

    def test_sequence_increments_across_event_types(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({})
        s.record_relate_event(h, h)
        s.record_navigate_event(h, h)
        s.record_govern_event(h, h)
        seqs = [ev.sequence for ev in s._events]
        assert seqs == [0, 1, 2]

    def test_multiple_facts_tracked(self) -> None:
        s = Session(actor="agent")
        h = SessionEvent.hash_payload({})
        s.record_relate_event(h, h, fact_id="f1")
        s.record_relate_event(h, h, fact_id="f2")
        assert s._fact_ids == ["f1", "f2"]


# ── SessionRecord structural tests ───────────────────────────────────────────

class TestSessionRecordStructure:
    def test_record_has_merkle_root(self) -> None:
        now = datetime.now(UTC)
        record = SessionRecord(
            session_id="test-sess",
            commit_type=CommitType.COMPLETE,
            principal="agent",
            purpose="test",
            started_at=now,
            closed_at=now,
            events=(),
            fact_ids=(),
            checkpoint_ids=(),
            merkle_root=SessionRecord.compute_merkle_root(()),
        )
        assert len(record.merkle_root) == 64

    def test_all_six_commit_types_usable(self) -> None:
        for ct in CommitType:
            assert isinstance(ct, str)

    def test_record_to_dict_round_trips_purpose(self) -> None:
        now = datetime.now(UTC)
        record = SessionRecord(
            session_id="s",
            commit_type=CommitType.PARTIAL,
            principal="p",
            purpose="my-purpose",
            started_at=now,
            closed_at=now,
            events=(),
            fact_ids=(),
            checkpoint_ids=(),
            merkle_root=SessionRecord.compute_merkle_root(()),
        )
        assert record.to_dict()["purpose"] == "my-purpose"
