"""Conformance adapter — verify Engine passes Phase 2 scenarios."""

from __future__ import annotations

import uuid

from tests.conformance_adapter import ConformanceAdapter


def _adapter_with_consent() -> ConformanceAdapter:
    a = ConformanceAdapter()
    a.add_consent_grant({"grant_id": "g1", "subject_id": "s1", "grantee_id": "conformance-test",
                         "operations": ["ingest", "query", "replay", "export"],
                         "purpose": "conformance-testing", "classification_max": 3,
                         "granted_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"})
    return a


def _prov() -> dict:  # type: ignore[type-arg]
    return {"source_id": "src", "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
            "chain_of_custody": ["src"], "classification": 0, "model_id": None}


def test_ingest_ok() -> None:
    r = _adapter_with_consent().ingest(data={"x": 1}, provenance=_prov(), purpose="conformance-testing", subject_id="s1")
    assert r["status"] == "ok"


def test_ingest_no_consent() -> None:
    r = ConformanceAdapter().ingest(data={"x": 1}, provenance=_prov(), purpose="t", subject_id="s1")
    assert r["status"] == "error" and r["data"]["error_code"] == "consent_required"


def test_ingest_crisis() -> None:
    r = ConformanceAdapter().ingest(data={"content": "I want to kill myself"}, provenance=_prov(), purpose="t", subject_id="s1")
    assert r["status"] == "crisis"


def test_commit_idempotent() -> None:
    a = ConformanceAdapter()
    key = str(uuid.uuid4())
    r1 = a.commit(event_type="app.t", payload={}, idempotency_key=key)
    r2 = a.commit(event_type="app.t", payload={}, idempotency_key=key)
    assert r1["audit_id"] == r2["audit_id"]


def test_replay_deterministic() -> None:
    a = ConformanceAdapter()
    c = a.commit(event_type="app.det", payload={"v": "fixed"})
    r1 = a.replay(audit_id=c["audit_id"])
    r2 = a.replay(audit_id=c["audit_id"])
    assert r1["data"] == r2["data"]


def test_review_not_found() -> None:
    a = ConformanceAdapter()
    r = a.review(audit_id="urn:aevum:audit:00000000-0000-7000-8000-000000000999")
    assert r["status"] == "error" and r["data"]["error_code"] == "review_not_found"


def test_get_ledger_entries() -> None:
    a = ConformanceAdapter()
    a.commit(event_type="app.e", payload={})
    entries = a.get_ledger_entries()
    assert len(entries) == 1
