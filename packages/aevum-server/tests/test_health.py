"""Tests for GET /v1/health."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_no_auth_required(client: TestClient) -> None:
    """Health endpoint must not require authentication (spec Section 10.2)."""
    r = client.get("/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "version" in r.json()


def test_health_has_security_headers(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "max-age=31536000" in r.headers.get("strict-transport-security", "")


def test_health_has_correlation_id(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert "x-request-id" in r.headers


def test_health_echoes_request_id(client: TestClient) -> None:
    sent_id = "my-trace-id-123"
    r = client.get("/v1/health", headers={"X-Request-ID": sent_id})
    assert r.headers.get("x-request-id") == sent_id


def test_health_has_rate_limit_headers(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert "x-ratelimit-limit" in r.headers
    assert "x-ratelimit-remaining" in r.headers
