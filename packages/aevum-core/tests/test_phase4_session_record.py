# SPDX-License-Identifier: Apache-2.0
"""Phase 4 tests: SessionEvent, SessionRecord, CommitType, EventType."""
from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import pytest

from aevum.core.session_record import (
    CommitType,
    EventType,
    SessionEvent,
    SessionRecord,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _make_event(seq: int, session_id: str = "sess-1") -> SessionEvent:
    payload = {"seq": seq}
    h = SessionEvent.hash_payload(payload)
    return SessionEvent(
        event_id=f"ev-{seq}",
        session_id=session_id,
        sequence=seq,
        event_type=EventType.RELATE,
        occurred_at=_now(),
        input_hash=h,
        output_hash=h,
        latency_ms=10,
        taint_labels=(),
    )


def _make_record(events: tuple = (), **overrides: object) -> SessionRecord:
    now = _now()
    root = SessionRecord.compute_merkle_root(events)
    defaults: dict = dict(
        session_id="sess-1",
        commit_type=CommitType.COMPLETE,
        principal="agent",
        purpose="test",
        started_at=now,
        closed_at=now,
        events=events,
        fact_ids=(),
        checkpoint_ids=(),
        merkle_root=root,
    )
    defaults.update(overrides)
    return SessionRecord(**defaults)


# ── CommitType ────────────────────────────────────────────────────────────────

class TestCommitType:
    def test_is_str_enum(self) -> None:
        assert issubclass(CommitType, StrEnum)

    def test_six_types_defined(self) -> None:
        assert len(CommitType) == 6

    def test_values(self) -> None:
        assert CommitType.COMPLETE == "complete"
        assert CommitType.CRISIS == "crisis"
        assert CommitType.EMERGENCY == "emergency"
        assert CommitType.PARTIAL == "partial"
        assert CommitType.VETOED == "vetoed"
        assert CommitType.TIMEOUT == "timeout"

    def test_round_trip_from_string(self) -> None:
        for ct in CommitType:
            assert CommitType(ct.value) is ct

    def test_all_values_are_strings(self) -> None:
        for ct in CommitType:
            assert isinstance(ct, str)


# ── EventType ─────────────────────────────────────────────────────────────────

class TestEventType:
    def test_is_str_enum(self) -> None:
        assert issubclass(EventType, StrEnum)

    def test_all_six_types_present(self) -> None:
        for name in ("relate", "navigate", "govern", "llm", "tool", "system"):
            assert EventType(name)

    def test_six_types_defined(self) -> None:
        assert len(EventType) == 6

    def test_round_trip_from_string(self) -> None:
        for et in EventType:
            assert EventType(et.value) is et


# ── SessionEvent ──────────────────────────────────────────────────────────────

class TestSessionEvent:
    def test_frozen(self) -> None:
        ev = _make_event(0)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            ev.sequence = 1  # type: ignore[misc]

    def test_negative_sequence_raises(self) -> None:
        h = SessionEvent.hash_payload({})
        with pytest.raises(ValueError):
            SessionEvent("id", "sess", -1, EventType.RELATE, _now(), h, h, 0, ())

    def test_short_input_hash_raises(self) -> None:
        h = SessionEvent.hash_payload({})
        with pytest.raises(ValueError):
            SessionEvent("id", "sess", 0, EventType.RELATE, _now(), "abc", h, 0, ())

    def test_short_output_hash_raises(self) -> None:
        h = SessionEvent.hash_payload({})
        with pytest.raises(ValueError):
            SessionEvent("id", "sess", 0, EventType.RELATE, _now(), h, "short", 0, ())

    def test_hash_payload_is_64_chars(self) -> None:
        h = SessionEvent.hash_payload({"key": "value"})
        assert len(h) == 64

    def test_hash_payload_deterministic(self) -> None:
        h1 = SessionEvent.hash_payload({"b": 2, "a": 1})
        h2 = SessionEvent.hash_payload({"a": 1, "b": 2})
        assert h1 == h2, "hash_payload must be key-order independent"

    def test_hash_payload_different_for_different_input(self) -> None:
        h1 = SessionEvent.hash_payload({"a": 1})
        h2 = SessionEvent.hash_payload({"a": 2})
        assert h1 != h2

    def test_metadata_defaults_to_empty_dict(self) -> None:
        h = SessionEvent.hash_payload({})
        ev = SessionEvent("id", "sess", 0, EventType.RELATE, _now(), h, h, 0, ())
        assert ev.metadata == {}

    def test_zero_latency_accepted(self) -> None:
        h = SessionEvent.hash_payload({})
        ev = SessionEvent("id", "sess", 0, EventType.NAVIGATE, _now(), h, h, 0, ())
        assert ev.latency_ms == 0

    def test_taint_labels_stored(self) -> None:
        h = SessionEvent.hash_payload({})
        ev = SessionEvent("id", "sess", 0, EventType.GOVERN, _now(), h, h, 5, ("READS_PRIVATE",))
        assert ev.taint_labels == ("READS_PRIVATE",)

    def test_all_event_types_constructable(self) -> None:
        h = SessionEvent.hash_payload({})
        for et in EventType:
            ev = SessionEvent("id", "sess", 0, et, _now(), h, h, 0, ())
            assert ev.event_type == et


# ── SessionRecord ─────────────────────────────────────────────────────────────

class TestSessionRecord:
    def test_frozen(self) -> None:
        r = _make_record()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            r.session_id = "other"  # type: ignore[misc]

    def test_empty_session_id_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_record(session_id="")

    def test_empty_purpose_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_record(purpose="")

    def test_closed_before_started_raises(self) -> None:
        now = _now()
        with pytest.raises(ValueError):
            _make_record(started_at=now, closed_at=now - timedelta(seconds=1))

    def test_bad_merkle_root_length_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_record(merkle_root="short")

    def test_duration_seconds_positive(self) -> None:
        now = _now()
        r = _make_record(started_at=now, closed_at=now + timedelta(seconds=5))
        assert r.duration_seconds >= 5.0

    def test_to_dict_serializable(self) -> None:
        r = _make_record()
        d = r.to_dict()
        json.dumps(d)  # must not raise

    def test_to_dict_has_required_keys(self) -> None:
        r = _make_record()
        d = r.to_dict()
        for key in ("session_id", "commit_type", "merkle_root", "event_count"):
            assert key in d

    def test_sigchain_entry_id_defaults_none(self) -> None:
        r = _make_record()
        assert r.sigchain_entry_id is None

    def test_tsa_token_hex_defaults_none(self) -> None:
        r = _make_record()
        assert r.tsa_token_hex is None

    def test_fact_ids_empty_tuple(self) -> None:
        r = _make_record()
        assert r.fact_ids == ()

    def test_checkpoint_ids_empty_tuple(self) -> None:
        r = _make_record()
        assert r.checkpoint_ids == ()

    def test_record_with_events(self) -> None:
        events = tuple(_make_event(i) for i in range(3))
        r = _make_record(events=events)
        assert len(r.events) == 3
        assert r.to_dict()["event_count"] == 3

    def test_duration_zero_for_same_timestamps(self) -> None:
        now = _now()
        r = _make_record(started_at=now, closed_at=now)
        assert r.duration_seconds == 0.0

    def test_to_dict_commit_type_is_string(self) -> None:
        r = _make_record(commit_type=CommitType.CRISIS)
        assert r.to_dict()["commit_type"] == "crisis"

    def test_to_dict_duration_seconds_present(self) -> None:
        r = _make_record()
        assert "duration_seconds" in r.to_dict()


# ── Merkle root ───────────────────────────────────────────────────────────────

class TestMerkleRoot:
    def test_empty_session_has_fixed_root(self) -> None:
        root = SessionRecord.compute_merkle_root(())
        assert root == hashlib.sha256(b"").hexdigest()
        assert len(root) == 64

    def test_single_event_produces_root(self) -> None:
        ev = _make_event(0)
        root = SessionRecord.compute_merkle_root((ev,))
        assert len(root) == 64
        assert root != hashlib.sha256(b"").hexdigest()

    def test_root_changes_when_event_changes(self) -> None:
        ev1 = _make_event(0)
        ev2 = _make_event(1)
        root1 = SessionRecord.compute_merkle_root((ev1,))
        root2 = SessionRecord.compute_merkle_root((ev2,))
        assert root1 != root2

    def test_root_order_invariant_via_sequence_sort(self) -> None:
        ev0 = _make_event(0)
        ev1 = _make_event(1)
        root_forward = SessionRecord.compute_merkle_root((ev0, ev1))
        root_reversed = SessionRecord.compute_merkle_root((ev1, ev0))
        # compute_merkle_root sorts by sequence — so order of tuple is irrelevant
        assert root_forward == root_reversed

    def test_two_events_produce_root(self) -> None:
        events = tuple(_make_event(i) for i in range(2))
        root = SessionRecord.compute_merkle_root(events)
        assert len(root) == 64

    def test_many_events_produce_root(self) -> None:
        events = tuple(_make_event(i) for i in range(10))
        root = SessionRecord.compute_merkle_root(events)
        assert len(root) == 64

    def test_root_is_deterministic(self) -> None:
        events = tuple(_make_event(i) for i in range(5))
        r1 = SessionRecord.compute_merkle_root(events)
        r2 = SessionRecord.compute_merkle_root(events)
        assert r1 == r2

    def test_odd_number_of_events(self) -> None:
        events = tuple(_make_event(i) for i in range(3))
        root = SessionRecord.compute_merkle_root(events)
        assert len(root) == 64

    def test_root_is_64_hex_chars(self) -> None:
        for n in (0, 1, 2, 3, 4, 7, 8, 15, 16):
            events = tuple(_make_event(i) for i in range(n))
            root = SessionRecord.compute_merkle_root(events)
            assert len(root) == 64
            int(root, 16)  # must be valid hex

    def test_different_event_counts_produce_different_roots(self) -> None:
        roots = set()
        for n in range(5):
            events = tuple(_make_event(i) for i in range(n))
            roots.add(SessionRecord.compute_merkle_root(events))
        assert len(roots) == 5, "Each event count should produce a unique root"
