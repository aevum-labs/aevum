# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Phase 6 endpoint tests for aevum-server:
  GET  /v1/conformance
  POST /v1/sessions
  GET  /v1/sessions/{id}/audit-pack
  GET  /v1/health (enhanced)

NO tests/__init__.py (standing rule Rule 01).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


TEST_API_KEY = "test-api-key-for-ci"


@pytest.fixture
def client() -> TestClient:
    from aevum.core.engine import Engine
    from aevum.server.app import create_app
    from aevum.server.core.config import Settings

    settings = Settings(api_key=TEST_API_KEY, otel_enabled=False)
    app = create_app(engine=Engine(), settings=settings)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def authed_client() -> TestClient:
    from aevum.core.engine import Engine
    from aevum.server.app import create_app
    from aevum.server.core.config import Settings

    settings = Settings(api_key=TEST_API_KEY, otel_enabled=False)
    app = create_app(engine=Engine(), settings=settings)
    return TestClient(
        app,
        headers={"X-Aevum-Key": TEST_API_KEY},
        raise_server_exceptions=False,
    )


class TestConformanceEndpoint:
    def test_conformance_returns_200(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        assert resp.status_code == 200

    def test_conformance_no_auth_required(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        assert resp.status_code == 200

    def test_conformance_returns_status_ok(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        assert data["status"] == "ok"

    def test_conformance_has_version(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        assert "version" in data

    def test_conformance_has_checks(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        assert "checks" in data

    def test_conformance_checks_has_named_graphs(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        graphs = data["checks"]["named_graphs"]
        assert graphs["knowledge"] == "urn:aevum:knowledge"
        assert graphs["provenance"] == "urn:aevum:provenance"
        assert graphs["consent"] == "urn:aevum:consent"

    def test_conformance_checks_five_functions(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        funcs = data["checks"]["five_functions"]
        for fn in ("ingest", "query", "review", "commit", "replay"):
            assert fn in funcs

    def test_conformance_checks_append_only_ledger(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        assert data["checks"]["append_only_ledger"] is True

    def test_conformance_checks_consent_precondition(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        data = resp.json()
        assert data["checks"]["consent_precondition"] is True

    def test_conformance_content_type_json(self, client: TestClient) -> None:
        resp = client.get("/v1/conformance")
        assert "application/json" in resp.headers.get("content-type", "")


class TestSessionsEndpoint:
    def test_open_session_returns_201_or_200(self, authed_client: TestClient) -> None:
        resp = authed_client.post("/v1/sessions")
        assert resp.status_code in (200, 201)

    def test_open_session_requires_auth(self, client: TestClient) -> None:
        resp = client.post("/v1/sessions")
        assert resp.status_code in (401, 403)

    def test_open_session_returns_session_id(self, authed_client: TestClient) -> None:
        resp = authed_client.post("/v1/sessions")
        data = resp.json()
        assert "session_id" in data

    def test_open_session_returns_audit_id(self, authed_client: TestClient) -> None:
        resp = authed_client.post("/v1/sessions")
        data = resp.json()
        assert "audit_id" in data
        assert data["audit_id"].startswith("urn:aevum:audit:")

    def test_open_session_status_opened(self, authed_client: TestClient) -> None:
        resp = authed_client.post("/v1/sessions")
        data = resp.json()
        assert data["status"] == "opened"

    def test_open_session_unique_ids(self, authed_client: TestClient) -> None:
        resp1 = authed_client.post("/v1/sessions")
        resp2 = authed_client.post("/v1/sessions")
        id1 = resp1.json()["session_id"]
        id2 = resp2.json()["session_id"]
        assert id1 != id2


class TestAuditPackEndpoint:
    def test_audit_pack_returns_200(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/v1/sessions/test-session-123/audit-pack")
        assert resp.status_code == 200

    def test_audit_pack_requires_auth(self, client: TestClient) -> None:
        resp = client.get("/v1/sessions/test-session-123/audit-pack")
        assert resp.status_code in (401, 403)

    def test_audit_pack_has_session_id(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/v1/sessions/my-session/audit-pack")
        data = resp.json()
        assert data["session_id"] == "my-session"

    def test_audit_pack_has_article12(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/v1/sessions/s1/audit-pack")
        data = resp.json()
        assert "article12" in data

    def test_audit_pack_named_graphs(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/v1/sessions/s1/audit-pack")
        data = resp.json()
        graphs = data["article12"]["named_graphs"]
        assert graphs["knowledge"] == "urn:aevum:knowledge"
        assert graphs["provenance"] == "urn:aevum:provenance"
        assert graphs["consent"] == "urn:aevum:consent"

    def test_audit_pack_has_version(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/v1/sessions/s1/audit-pack")
        data = resp.json()
        assert "version" in data


class TestHealthEnhanced:
    def test_health_still_returns_200(self, client: TestClient) -> None:
        resp = client.get("/v1/health")
        assert resp.status_code == 200

    def test_health_has_status(self, client: TestClient) -> None:
        resp = client.get("/v1/health")
        data = resp.json()
        assert "status" in data
        assert data["status"] in ("ok", "degraded")

    def test_health_has_version(self, client: TestClient) -> None:
        resp = client.get("/v1/health")
        data = resp.json()
        assert "version" in data
