"""Tests for /v1/ingest, /v1/query, /v1/commit, /v1/replay, /v1/review."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

# ── ingest ──────────────────────────────────────────────────────────────────

def test_ingest_ok(authed_client: TestClient, valid_ingest_body: dict) -> None:
    r = authed_client.post("/v1/ingest", json=valid_ingest_body)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["audit_id"].startswith("urn:aevum:audit:")


def test_ingest_no_consent_returns_200_error_envelope(
    client: TestClient, valid_ingest_body: dict
) -> None:
    """No consent — kernel returns error OutputEnvelope, not HTTP error."""
    r = client.post(
        "/v1/ingest",
        json=valid_ingest_body,
        headers={"X-Aevum-Key": "test-api-key-for-ci"},
    )
    # Auth passes but kernel rejects for consent
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "error"
    assert body["data"]["error_code"] == "consent_required"


def test_ingest_crisis_content(authed_client: TestClient) -> None:
    r = authed_client.post("/v1/ingest", json={
        "data": {"content": "I want to kill myself"},
        "provenance": {"source_id": "test", "chain_of_custody": ["test"],
                       "classification": 0, "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
                       "model_id": None},
        "purpose": "test", "subject_id": "subject-1",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "crisis"


def test_ingest_idempotency(authed_client: TestClient, valid_ingest_body: dict) -> None:
    key = str(uuid.uuid4())
    r1 = authed_client.post(
        "/v1/ingest", json=valid_ingest_body,
        headers={"Idempotency-Key": key},
    )
    r2 = authed_client.post(
        "/v1/ingest", json=valid_ingest_body,
        headers={"Idempotency-Key": key},
    )
    assert r1.json()["audit_id"] == r2.json()["audit_id"]


# ── query ────────────────────────────────────────────────────────────────────

def test_query_ok(authed_client: TestClient, valid_ingest_body: dict) -> None:
    authed_client.post("/v1/ingest", json=valid_ingest_body)
    r = authed_client.post("/v1/query", json={
        "purpose": "integration-testing",
        "subject_ids": ["subject-1"],
    })
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── commit ───────────────────────────────────────────────────────────────────

def test_commit_ok(authed_client: TestClient) -> None:
    r = authed_client.post("/v1/commit", json={
        "event_type": "app.test_event",
        "payload": {"k": "v"},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["audit_id"].startswith("urn:aevum:audit:")


def test_commit_idempotency(authed_client: TestClient) -> None:
    key = str(uuid.uuid4())
    r1 = authed_client.post(
        "/v1/commit",
        json={"event_type": "app.idem", "payload": {}},
        headers={"Idempotency-Key": key},
    )
    r2 = authed_client.post(
        "/v1/commit",
        json={"event_type": "app.idem", "payload": {}},
        headers={"Idempotency-Key": key},
    )
    assert r1.json()["audit_id"] == r2.json()["audit_id"]


def test_commit_reserved_prefix_returns_error_envelope(authed_client: TestClient) -> None:
    r = authed_client.post("/v1/commit", json={
        "event_type": "ingest.fake",
        "payload": {},
    })
    assert r.status_code == 200
    assert r.json()["status"] == "error"
    assert r.json()["data"]["error_code"] == "reserved_event_type"


# ── replay ───────────────────────────────────────────────────────────────────

def test_replay_ok(authed_client: TestClient) -> None:
    committed = authed_client.post("/v1/commit", json={
        "event_type": "app.replayable",
        "payload": {"v": 42},
    }).json()
    r = authed_client.get(f"/v1/replay/{committed['audit_id']}")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["data"]["replayed_payload"]["v"] == 42


def test_replay_not_found(authed_client: TestClient) -> None:
    r = authed_client.get(
        "/v1/replay/urn:aevum:audit:00000000-0000-7000-8000-000000000999"
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"
    assert r.json()["data"]["error_code"] == "replay_not_found"


def test_replay_deterministic(authed_client: TestClient) -> None:
    committed = authed_client.post("/v1/commit", json={
        "event_type": "app.det", "payload": {"x": "fixed"},
    }).json()
    r1 = authed_client.get(f"/v1/replay/{committed['audit_id']}")
    r2 = authed_client.get(f"/v1/replay/{committed['audit_id']}")
    assert r1.json()["data"] == r2.json()["data"]


# ── review ───────────────────────────────────────────────────────────────────

def test_review_not_found(authed_client: TestClient) -> None:
    r = authed_client.get(
        "/v1/review/urn:aevum:audit:00000000-0000-7000-8000-000000000999"
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"
    assert r.json()["data"]["error_code"] == "review_not_found"


# ── OpenAPI ──────────────────────────────────────────────────────────────────

def test_openapi_schema_served(authed_client: TestClient) -> None:
    r = authed_client.get("/v1/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert schema["info"]["title"] == "Aevum HTTP API"
    assert "/v1/health" in schema["paths"] or "/v1/ingest" in schema["paths"]
