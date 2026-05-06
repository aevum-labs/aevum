"""Behavioral tests for all five functions via the Engine."""

from __future__ import annotations

from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine


def _grant(subject_id: str = "s1", ops: list[str] | None = None) -> ConsentGrant:
    return ConsentGrant(grant_id="g1", subject_id=subject_id, grantee_id="actor",
                        operations=ops or ["ingest", "query", "replay", "export"],
                        purpose="unit-testing", classification_max=3,
                        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z")


def _prov() -> dict:  # type: ignore[type-arg]
    return {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}


def test_commit_ok() -> None:
    e = Engine()
    r = e.commit(event_type="app.test", payload={"k": "v"}, actor="actor")
    assert r.status == "ok"
    assert r.audit_id.startswith("urn:aevum:audit:")


def test_commit_idempotency() -> None:
    e = Engine()
    r1 = e.commit(event_type="app.t", payload={}, actor="a", idempotency_key="k1")
    r2 = e.commit(event_type="app.t", payload={}, actor="a", idempotency_key="k1")
    assert r1.audit_id == r2.audit_id
    assert e.ledger_count() == 2  # session.start + one deduplicated commit


def test_commit_reserved_prefix() -> None:
    e = Engine()
    r = e.commit(event_type="ingest.fake", payload={}, actor="a")
    assert r.status == "error"
    assert r.data["error_code"] == "reserved_event_type"


def test_ingest_ok() -> None:
    e = Engine()
    e.add_consent_grant(_grant())
    r = e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")
    assert r.status == "ok"


def test_ingest_no_consent() -> None:
    e = Engine()
    r = e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")
    assert r.status == "error"
    assert r.data["error_code"] == "consent_required"


def test_ingest_no_provenance() -> None:
    e = Engine()
    e.add_consent_grant(_grant())
    r = e.ingest(data={"x": 1}, provenance={}, purpose="test", subject_id="s1", actor="actor")
    assert r.status == "error"
    assert r.data["error_code"] == "provenance_required"


def test_query_ok() -> None:
    e = Engine()
    e.add_consent_grant(_grant())
    e.ingest(data={"x": 1}, provenance=_prov(), purpose="test", subject_id="s1", actor="actor")
    r = e.query(purpose="test", subject_ids=["s1"], actor="actor")
    assert r.status == "ok"


def test_query_no_consent() -> None:
    e = Engine()
    r = e.query(purpose="test", subject_ids=["s1"], actor="actor")
    assert r.status == "error"
    assert r.data["error_code"] == "consent_required"


def test_replay_existing() -> None:
    e = Engine()
    e.add_consent_grant(_grant())
    c = e.commit(event_type="app.r", payload={"v": 42}, actor="actor")
    r = e.replay(audit_id=c.audit_id, actor="actor")
    assert r.status == "ok"
    assert r.data["replayed_payload"]["v"] == 42


def test_replay_not_found() -> None:
    e = Engine()
    r = e.replay(audit_id="urn:aevum:audit:00000000-0000-7000-8000-000000000999", actor="a")
    assert r.status == "error"
    assert r.data["error_code"] == "replay_not_found"


def test_replay_deterministic() -> None:
    e = Engine()
    c = e.commit(event_type="app.d", payload={"x": 1}, actor="a")
    r1 = e.replay(audit_id=c.audit_id, actor="a")
    r2 = e.replay(audit_id=c.audit_id, actor="a")
    assert r1.data == r2.data


def test_review_cycle() -> None:
    e = Engine()
    rid = e.create_review(proposed_action="delete data", reason="test", actor="a")
    polled = e.review(audit_id=rid, actor="a")
    assert polled.status == "pending_review"
    approved = e.review(audit_id=rid, actor="a", action="approve")
    assert approved.status == "ok"


def test_review_veto() -> None:
    e = Engine()
    rid = e.create_review(proposed_action="action", reason="test", actor="a")
    r = e.review(audit_id=rid, actor="a", action="veto")
    assert r.status == "error"
    assert r.data["error_code"] == "review_vetoed"


def test_review_not_found() -> None:
    e = Engine()
    r = e.review(audit_id="urn:aevum:audit:00000000-0000-7000-8000-000000000999", actor="a")
    assert r.status == "error"
    assert r.data["error_code"] == "review_not_found"


def test_sigchain_integrity() -> None:
    e = Engine()
    e.add_consent_grant(_grant())
    for i in range(5):
        e.commit(event_type=f"app.e{i}", payload={"i": i}, actor="a")
    assert e.verify_sigchain() is True


def test_ingest_model_context_stored_in_payload() -> None:
    """model_context OTel keys are stored in the AuditEvent payload."""
    e = Engine()
    e.add_consent_grant(ConsentGrant(
        grant_id="g1", subject_id="u1", grantee_id="agent",
        operations=["ingest"], purpose="test", classification_max=0,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    result = e.ingest(
        data={"note": "test"},
        provenance={"source_id": "test", "chain_of_custody": ["test"], "classification": 0},
        purpose="test",
        subject_id="u1",
        actor="agent",
        model_context={
            "gen_ai.request.model": "gpt-4.1",
            "gen_ai.system": "openai",
            "gen_ai.conversation.id": "conv-123",
            "unknown_key": "should_be_ignored",
        },
    )
    assert result.status == "ok"
    last_event = e._ledger.all_events()[-1]
    assert last_event.payload.get("gen_ai.request.model") == "gpt-4.1"
    assert last_event.payload.get("gen_ai.system") == "openai"
    assert last_event.payload.get("gen_ai.conversation.id") == "conv-123"
    assert "unknown_key" not in last_event.payload


def test_ingest_model_context_none_is_noop() -> None:
    """model_context=None must not affect existing behavior."""
    e = Engine()
    e.add_consent_grant(ConsentGrant(
        grant_id="g1", subject_id="u1", grantee_id="agent",
        operations=["ingest"], purpose="test", classification_max=0,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    result = e.ingest(
        data={"note": "test"},
        provenance={"source_id": "test", "chain_of_custody": ["test"], "classification": 0},
        purpose="test",
        subject_id="u1",
        actor="agent",
    )
    assert result.status == "ok"
    last_event = e._ledger.all_events()[-1]
    for key in ("gen_ai.request.model", "gen_ai.system", "gen_ai.conversation.id"):
        assert key not in last_event.payload


import pytest


def test_record_capture_gap_writes_event() -> None:
    """record_capture_gap() must write a signed capture.gap event."""
    engine = Engine()
    event = engine.record_capture_gap(
        gap_type="llm",
        actor="billing-agent",
        episode_id="ep-001",
        reason="direct_api_call",
        model_hint="gpt-4.1",
    )
    assert event.event_type == "capture.gap"
    assert event.actor == "billing-agent"
    assert event.episode_id == "ep-001"
    assert event.payload["gap_type"] == "llm"
    assert event.payload["reason"] == "direct_api_call"
    assert event.payload.get("model_hint") == "gpt-4.1"
    assert engine.verify_sigchain() is True


def test_record_capture_gap_invalid_type() -> None:
    """gap_type must be one of the valid values."""
    engine = Engine()
    with pytest.raises(ValueError, match="gap_type must be one of"):
        engine.record_capture_gap(gap_type="unknown", actor="a")


def test_record_capture_gap_empty_actor() -> None:
    engine = Engine()
    with pytest.raises(ValueError, match="actor must be a non-empty string"):
        engine.record_capture_gap(gap_type="llm", actor="")


def test_record_capture_gap_in_chain() -> None:
    """capture.gap events must appear in the sigchain between other events."""
    engine = Engine()
    engine.add_consent_grant(ConsentGrant(
        grant_id="g1", subject_id="u1", grantee_id="agent",
        operations=["ingest"], purpose="test",
        classification_max=0,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))
    engine.ingest(
        data={"x": 1},
        provenance={"source_id": "s", "chain_of_custody": ["s"], "classification": 0},
        purpose="test", subject_id="u1", actor="agent",
    )
    engine.record_capture_gap(gap_type="llm", actor="agent", episode_id=None)

    entries = engine.get_ledger_entries()
    event_types = [e["event_type"] for e in entries]
    assert "capture.gap" in event_types
    assert engine.verify_sigchain() is True


def test_session_start_uses_complication_registry() -> None:
    """session.start capture_surface must reflect registration, not installation."""
    engine = Engine()
    session = engine.get_ledger_entries()[0]
    assert session["event_type"] == "session.start"
    # Without any complications registered, both must be False
    assert session["payload"]["capture_surface"]["llm"] is False
    assert session["payload"]["capture_surface"]["mcp"] is False
