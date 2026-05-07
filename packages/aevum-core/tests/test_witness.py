"""Tests for Phase 12a — Context Witness (TOCTOU protection)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine
from aevum.core.witness import (
    StaleContextError,
    Witness,
    _digest_results,
    capture,
    revalidate,
)


def _grant(subject_id: str = "s1") -> ConsentGrant:
    return ConsentGrant(
        grant_id="g1",
        subject_id=subject_id,
        grantee_id="actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="unit-testing",
        classification_max=3,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    )


def _prov() -> dict[str, Any]:
    return {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}


# ── Group A: Witness unit tests (no engine) ───────────────────────────────────


def test_a1_capture_returns_witness_with_correct_types() -> None:
    """A1: capture() returns a Witness with correct field types."""
    ledger = MagicMock()
    ledger.max_sequence_for_subjects.return_value = 5
    results: dict[str, Any] = {"s1": {"x": 1}}

    w = capture(subject_ids=["s1"], results=results, ledger=ledger)

    assert isinstance(w, Witness)
    assert isinstance(w.sequence_watermark, int)
    assert isinstance(w.subject_ids, tuple)
    assert isinstance(w.result_digest, str)
    assert isinstance(w.captured_at_ns, int)
    assert w.sequence_watermark == 5
    assert w.subject_ids == ("s1",)


def test_a2_witness_dict_round_trip() -> None:
    """A2: Witness.as_dict() round-trips through Witness.from_dict()."""
    original = Witness(
        sequence_watermark=7,
        subject_ids=("s1", "s2"),
        result_digest="abc123",
        captured_at_ns=1_000_000,
    )
    d = original.as_dict()
    restored = Witness.from_dict(d)

    assert restored == original
    assert restored.sequence_watermark == 7
    assert restored.subject_ids == ("s1", "s2")
    assert restored.result_digest == "abc123"
    assert restored.captured_at_ns == 1_000_000


def test_a3_digest_results_is_deterministic() -> None:
    """A3: _digest_results() is deterministic (same input, same hash)."""
    results: dict[str, Any] = {"s1": {"name": "alice", "score": 42}}
    d1 = _digest_results(results)
    d2 = _digest_results(results)
    assert d1 == d2
    assert len(d1) == 64  # SHA-256 hex digest length


def test_a4_digest_results_changes_when_results_change() -> None:
    """A4: _digest_results() changes when results change."""
    r1: dict[str, Any] = {"s1": {"score": 1}}
    r2: dict[str, Any] = {"s1": {"score": 2}}
    assert _digest_results(r1) != _digest_results(r2)


# ── Group B: revalidate() unit tests (mock ledger) ────────────────────────────


def test_b1_revalidate_passes_when_watermark_and_digest_match() -> None:
    """B1: revalidate() passes when watermark and digest match."""
    ledger = MagicMock()
    ledger.max_sequence_for_subjects.return_value = 3
    results: dict[str, Any] = {"s1": {"v": 1}}

    w = Witness(
        sequence_watermark=3,
        subject_ids=("s1",),
        result_digest=_digest_results(results),
        captured_at_ns=0,
    )
    # Should not raise
    revalidate(w, results, ledger)


def test_b2_revalidate_raises_when_watermark_advanced() -> None:
    """B2: revalidate() raises StaleContextError when watermark advanced."""
    ledger = MagicMock()
    ledger.max_sequence_for_subjects.return_value = 10  # advanced from 3
    results: dict[str, Any] = {"s1": {"v": 1}}

    w = Witness(
        sequence_watermark=3,
        subject_ids=("s1",),
        result_digest=_digest_results(results),
        captured_at_ns=0,
    )
    with pytest.raises(StaleContextError):
        revalidate(w, results, ledger)


def test_b3_revalidate_raises_when_digest_changed() -> None:
    """B3: revalidate() raises StaleContextError when digest changed."""
    ledger = MagicMock()
    ledger.max_sequence_for_subjects.return_value = 3  # watermark unchanged
    original_results: dict[str, Any] = {"s1": {"v": 1}}
    new_results: dict[str, Any] = {"s1": {"v": 999}}  # data changed

    w = Witness(
        sequence_watermark=3,
        subject_ids=("s1",),
        result_digest=_digest_results(original_results),
        captured_at_ns=0,
    )
    with pytest.raises(StaleContextError):
        revalidate(w, new_results, ledger)


def test_b4_stale_context_error_carries_watermark_values() -> None:
    """B4: StaleContextError carries old/new watermark values."""
    ledger = MagicMock()
    ledger.max_sequence_for_subjects.return_value = 99
    results: dict[str, Any] = {"s1": {"v": 1}}

    w = Witness(
        sequence_watermark=5,
        subject_ids=("s1",),
        result_digest=_digest_results(results),
        captured_at_ns=0,
    )
    with pytest.raises(StaleContextError) as exc_info:
        revalidate(w, results, ledger)

    err = exc_info.value
    assert err.old_watermark == 5
    assert err.new_watermark == 99


# ── Group C: Integration via Engine ──────────────────────────────────────────


def test_c1_query_with_capture_witness_true_returns_witness() -> None:
    """C1: query() with capture_witness=True returns witness in data["witness"]."""
    e = Engine()
    e.add_consent_grant(_grant())
    e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")

    r = e.query(purpose="test", subject_ids=["s1"], actor="actor", capture_witness=True)

    assert r.status == "ok"
    assert "witness" in r.data
    w = r.data["witness"]
    assert "sequence_watermark" in w
    assert "subject_ids" in w
    assert "result_digest" in w
    assert "captured_at_ns" in w


def test_c2_query_with_capture_witness_false_returns_no_witness() -> None:
    """C2: query() with capture_witness=False returns no witness key."""
    e = Engine()
    e.add_consent_grant(_grant())
    e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")

    r = e.query(purpose="test", subject_ids=["s1"], actor="actor", capture_witness=False)

    assert r.status == "ok"
    assert "witness" not in r.data


def test_c3_commit_with_valid_witness_returns_ok() -> None:
    """C3: commit() with valid witness from a clean query() returns status="ok"."""
    e = Engine()
    e.add_consent_grant(_grant())
    e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")

    result = e.query(purpose="test", subject_ids=["s1"], actor="actor", capture_witness=True)
    witness = result.data["witness"]

    committed = e.commit(
        event_type="app.decision",
        payload={"choice": "proceed"},
        actor="actor",
        witness=witness,
    )

    assert committed.status == "ok"
    assert committed.data.get("committed") is True


def test_c4_commit_with_stale_witness_returns_stale_context_error() -> None:
    """C4: commit() with stale witness (ingest after query) returns stale_context error."""
    e = Engine()
    e.add_consent_grant(_grant())

    # Step 1: initial ingest
    e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")

    # Step 2: query captures witness
    result = e.query(purpose="test", subject_ids=["s1"], actor="actor", capture_witness=True)
    witness = result.data["witness"]

    # Step 4: new ingest makes context stale
    e.ingest(data={"x": 2}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")

    # Step 5: commit with now-stale witness
    stale = e.commit(
        event_type="app.decision",
        payload={"choice": "proceed"},
        actor="actor",
        witness=witness,
    )

    assert stale.status == "error"
    assert stale.data["error_code"] == "stale_context"
