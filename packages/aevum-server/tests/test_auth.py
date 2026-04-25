"""Tests for authentication enforcement."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_ingest_no_auth_returns_401(client: TestClient, valid_ingest_body: dict) -> None:
    r = client.post("/v1/ingest", json=valid_ingest_body)
    assert r.status_code == 401


def test_ingest_wrong_key_returns_401(client: TestClient, valid_ingest_body: dict) -> None:
    r = client.post(
        "/v1/ingest",
        json=valid_ingest_body,
        headers={"X-Aevum-Key": "wrong-key"},
    )
    assert r.status_code == 401


def test_query_no_auth_returns_401(client: TestClient) -> None:
    r = client.post("/v1/query", json={"purpose": "test", "subject_ids": ["s1"]})
    assert r.status_code == 401


def test_commit_no_auth_returns_401(client: TestClient) -> None:
    r = client.post("/v1/commit", json={"event_type": "app.test", "payload": {}})
    assert r.status_code == 401


def test_replay_no_auth_returns_401(client: TestClient) -> None:
    r = client.get("/v1/replay/urn:aevum:audit:00000000-0000-7000-8000-000000000001")
    assert r.status_code == 401


def test_health_no_auth_returns_200(client: TestClient) -> None:
    """Health is the only unauthenticated endpoint."""
    r = client.get("/v1/health")
    assert r.status_code == 200
