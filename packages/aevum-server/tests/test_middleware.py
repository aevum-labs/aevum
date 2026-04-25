"""Tests for middleware — correlation IDs, security headers, rate limits."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_security_headers_present(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "max-age=31536000" in r.headers["strict-transport-security"]
    assert r.headers["content-security-policy"] == "default-src 'none'"


def test_correlation_id_generated_when_absent(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert "x-request-id" in r.headers
    assert len(r.headers["x-request-id"]) > 0


def test_correlation_id_echoed(client: TestClient) -> None:
    r = client.get("/v1/health", headers={"X-Request-ID": "trace-abc"})
    assert r.headers["x-request-id"] == "trace-abc"


def test_rate_limit_headers_present(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert "x-ratelimit-limit" in r.headers
    assert "x-ratelimit-remaining" in r.headers
    assert "x-ratelimit-reset" in r.headers


def test_response_time_header_present(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert "x-response-time-ms" in r.headers
    assert int(r.headers["x-response-time-ms"]) >= 0
