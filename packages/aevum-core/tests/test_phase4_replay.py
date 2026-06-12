# SPDX-License-Identifier: Apache-2.0
"""Phase 4 tests: ReplayEngine, replay(), diff(), fork_at_step()."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aevum.core.replay import EventReplayResult, ReplayEngine, ReplayResult
from aevum.core.session_record import (
    CommitType,
    EventType,
    SessionEvent,
    SessionRecord,
)


def _make_event(seq: int, session_id: str = "sess-1") -> SessionEvent:
    h = SessionEvent.hash_payload({"seq": seq})
    return SessionEvent(
        event_id=f"{session_id}-ev-{seq}",   # session-qualified to avoid PK collisions
        session_id=session_id,
        sequence=seq,
        event_type=EventType.RELATE,
        occurred_at=datetime.now(UTC),
        input_hash=h,
        output_hash=h,
        latency_ms=10,
        taint_labels=(),
    )


def _write_session(
    engine: ReplayEngine,
    session_id: str,
    n_events: int,
    commit_type: CommitType = CommitType.COMPLETE,
) -> SessionRecord:
    now = datetime.now(UTC)
    events = tuple(_make_event(i, session_id) for i in range(n_events))
    root = SessionRecord.compute_merkle_root(events)
    engine._conn.execute(
        "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
        (session_id, commit_type.value, "agent", "test",
         now.isoformat(), now.isoformat(), len(events), 0, 0, root),
    )
    for ev in events:
        engine._conn.execute(
            "INSERT OR IGNORE INTO session_events VALUES (?,?,?,?,?,?,?,?)",
            (ev.event_id, session_id, ev.sequence, ev.event_type.value,
             ev.occurred_at.isoformat(), ev.input_hash, ev.output_hash, ev.latency_ms),
        )
    engine._conn.commit()
    return SessionRecord(
        session_id=session_id, commit_type=commit_type, principal="agent",
        purpose="test", started_at=now, closed_at=now,
        events=events, fact_ids=(), checkpoint_ids=(), merkle_root=root,
    )


# ── ReplayEngine ──────────────────────────────────────────────────────────────

class TestReplayEngine:
    def test_load_session_record_found(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 3)
        record = engine.load_session_record("sess-1")
        assert record.session_id == "sess-1"
        assert len(record.events) == 3

    def test_load_session_record_not_found(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        with pytest.raises(ValueError, match="not found"):
            engine.load_session_record("nonexistent")

    def test_load_session_record_commit_type(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 2, CommitType.CRISIS)
        record = engine.load_session_record("sess-1")
        assert record.commit_type == CommitType.CRISIS

    def test_load_session_event_types_preserved(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 2)
        record = engine.load_session_record("sess-1")
        for ev in record.events:
            assert ev.event_type == EventType.RELATE

    def test_replay_all_matched_for_intact_session(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 5)
        result = engine.replay("sess-1")
        assert result.all_matched
        assert result.first_divergence is None
        assert len(result.event_results) == 5

    def test_replay_empty_session(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "empty-sess", 0)
        result = engine.replay("empty-sess")
        assert result.all_matched
        assert len(result.event_results) == 0

    def test_replay_detects_merkle_root_tampering(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-tamper", 3)
        engine._conn.execute(
            "UPDATE sessions SET merkle_root = ? WHERE session_id = ?",
            ("a" * 64, "sess-tamper"),
        )
        engine._conn.commit()
        result = engine.replay("sess-tamper")
        assert not result.all_matched, "Tampered Merkle root must be detected"

    def test_replay_result_has_session_id(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 2)
        result = engine.replay("sess-1")
        assert result.session_id == "sess-1"

    def test_replay_result_has_original_merkle_root(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 3)
        record = engine.load_session_record("sess-1")
        result = engine.replay("sess-1")
        assert result.original_merkle_root == record.merkle_root

    def test_event_replay_result_matched_true(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-1", 2)
        result = engine.replay("sess-1")
        for er in result.event_results:
            assert er.matched
            assert not er.diverged


# ── ReplayResult ──────────────────────────────────────────────────────────────

class TestReplayResult:
    def test_from_event_results_empty(self) -> None:
        import hashlib
        result = ReplayResult.from_event_results("s1", "a" * 64, [])
        assert result.all_matched
        assert result.first_divergence is None
        assert result.replayed_merkle_root == hashlib.sha256(b"").hexdigest()

    def test_from_event_results_all_matched(self) -> None:
        h = "a" * 64
        ers = [
            EventReplayResult("e0", 0, EventType.RELATE, h, h, True),
            EventReplayResult("e1", 1, EventType.RELATE, h, h, True),
        ]
        result = ReplayResult.from_event_results("s1", "b" * 64, ers)
        assert result.all_matched
        assert result.first_divergence is None

    def test_from_event_results_first_divergence(self) -> None:
        h = "a" * 64
        h2 = "b" * 64
        ers = [
            EventReplayResult("e0", 0, EventType.RELATE, h, h, True),
            EventReplayResult("e1", 1, EventType.RELATE, h, h2, False),
            EventReplayResult("e2", 2, EventType.RELATE, h, h, True),
        ]
        result = ReplayResult.from_event_results("s1", "c" * 64, ers)
        assert not result.all_matched
        assert result.first_divergence == 1


# ── DiffResult ────────────────────────────────────────────────────────────────

class TestDiff:
    def test_identical_sessions_diff(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-a", 3)
        _write_session(engine, "sess-b", 3)
        diff = engine.diff("sess-a", "sess-b")
        assert diff.identical

    def test_different_event_counts_diverge(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-a", 3)
        _write_session(engine, "sess-b", 5)
        diff = engine.diff("sess-a", "sess-b")
        assert not diff.identical

    def test_diff_result_has_session_ids(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sa", 1)
        _write_session(engine, "sb", 1)
        diff = engine.diff("sa", "sb")
        assert diff.session_id_a == "sa"
        assert diff.session_id_b == "sb"

    def test_diff_events_in_a_and_b(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sess-a", 4)
        _write_session(engine, "sess-b", 2)
        diff = engine.diff("sess-a", "sess-b")
        assert diff.events_in_a == 4
        assert diff.events_in_b == 2

    def test_identical_has_no_downstream_effects(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sa", 3)
        _write_session(engine, "sb", 3)
        diff = engine.diff("sa", "sb")
        assert diff.downstream_effects == ()

    def test_first_divergence_none_for_identical(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sa", 2)
        _write_session(engine, "sb", 2)
        diff = engine.diff("sa", "sb")
        assert diff.first_divergence is None

    def test_diff_empty_sessions_identical(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "sa", 0)
        _write_session(engine, "sb", 0)
        diff = engine.diff("sa", "sb")
        assert diff.identical


# ── fork_at_step ──────────────────────────────────────────────────────────────

class TestForkAtStep:
    def test_fork_returns_new_id(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 5)
        fork_id = engine.fork_at_step("original", 3)
        assert fork_id != "original"
        assert fork_id.startswith("fork-")

    def test_fork_inherits_events_up_to_step(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 5)
        fork_id = engine.fork_at_step("original", 3)
        fork = engine.load_session_record(fork_id)
        assert len(fork.events) == 3

    def test_fork_at_zero_has_no_events(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 5)
        fork_id = engine.fork_at_step("original", 0)
        fork = engine.load_session_record(fork_id)
        assert len(fork.events) == 0

    def test_fork_at_end_has_all_events(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 5)
        fork_id = engine.fork_at_step("original", 5)
        fork = engine.load_session_record(fork_id)
        assert len(fork.events) == 5

    def test_fork_out_of_range_raises(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 3)
        with pytest.raises(ValueError):
            engine.fork_at_step("original", 99)

    def test_fork_merkle_root_consistent(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 5)
        fork_id = engine.fork_at_step("original", 3)
        fork = engine.load_session_record(fork_id)
        recomputed = SessionRecord.compute_merkle_root(fork.events)
        assert fork.merkle_root == recomputed

    def test_fork_commit_type_is_partial(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 4)
        fork_id = engine.fork_at_step("original", 2)
        fork = engine.load_session_record(fork_id)
        assert fork.commit_type == CommitType.PARTIAL

    def test_fork_purpose_references_original(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 4)
        fork_id = engine.fork_at_step("original", 2)
        fork = engine.load_session_record(fork_id)
        assert "original" in fork.purpose

    def test_fork_negative_step_raises(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 3)
        with pytest.raises(ValueError):
            engine.fork_at_step("original", -1)

    def test_two_forks_have_different_ids(self, tmp_path: object) -> None:
        engine = ReplayEngine(tmp_path / "test.db")  # type: ignore[operator]
        _write_session(engine, "original", 5)
        fork1 = engine.fork_at_step("original", 2)
        fork2 = engine.fork_at_step("original", 2)
        assert fork1 != fork2
