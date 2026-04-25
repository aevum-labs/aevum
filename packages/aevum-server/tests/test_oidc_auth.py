"""
Tests for OIDC Bearer token auth in aevum-server.

Uses a MockOidcComplication installed on the engine — no real IDP required.
Validates the fail-closed behaviour and actor resolution flow.
"""

from __future__ import annotations

from typing import Any

import pytest
from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine
from fastapi.testclient import TestClient

from aevum.server.app import create_app
from aevum.server.core.config import Settings

TEST_KEY = "test-api-key-for-ci"
VALID_BEARER_TOKEN = "valid-oidc-token"
OIDC_ACTOR = "oidc-resolved-actor"


class MockOidcComplication:
    """Fake OIDC complication — validates a single hard-coded token."""

    name = "oidc"
    version = "0.1.0"
    capabilities = ["oidc-validation", "actor-resolution"]

    async def run(self, ctx: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        token = ctx.get("metadata", {}).get("bearer_token", "")
        if token == VALID_BEARER_TOKEN:
            return {"oidc_validated": True, "resolved_actor": OIDC_ACTOR, "resolved_classification": 0}
        return {"oidc_validated": False, "reason": "invalid mock token"}

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": "Mock OIDC complication for testing",
            "capabilities": list(self.capabilities),
            "classification_max": 0,
            "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    def health(self) -> bool:
        return True


def _settings() -> Settings:
    return Settings(api_key=TEST_KEY, otel_enabled=False)


def _engine_with_oidc() -> Engine:
    """Engine with OIDC complication installed and consent for the OIDC actor."""
    engine = Engine()
    engine.install_complication(MockOidcComplication(), auto_approve=True)
    engine.add_consent_grant(ConsentGrant(
        grant_id="oidc-grant",
        subject_id="subject-oidc",
        grantee_id=OIDC_ACTOR,
        operations=["ingest", "query", "replay", "export"],
        purpose="oidc-testing",
        classification_max=3,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))
    return engine


def _engine_no_oidc() -> Engine:
    """Engine with no OIDC complication installed."""
    return Engine()


@pytest.fixture
def client_with_oidc() -> TestClient:
    app = create_app(engine=_engine_with_oidc(), settings=_settings())
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client_no_oidc() -> TestClient:
    app = create_app(engine=_engine_no_oidc(), settings=_settings())
    return TestClient(app, raise_server_exceptions=False)


# ── Fail-closed: no OIDC complication installed ───────────────────────────────

def test_bearer_without_oidc_complication_returns_401(client_no_oidc: TestClient) -> None:
    """When no OIDC complication is active, Bearer tokens must be rejected (fail-closed)."""
    r = client_no_oidc.get(
        "/v1/replay/urn:aevum:audit:00000000-0000-7000-8000-000000000001",
        headers={"Authorization": f"Bearer {VALID_BEARER_TOKEN}"},
    )
    assert r.status_code == 401
    body = r.json()
    detail_msg: str = body["detail"]["detail"]
    assert "oidc" in detail_msg.lower() or "bearer" in detail_msg.lower()


# ── Valid Bearer token resolves actor ─────────────────────────────────────────

def test_valid_bearer_resolves_actor_and_allows_ingest(client_with_oidc: TestClient) -> None:
    """A valid Bearer token resolves the actor via the OIDC complication."""
    r = client_with_oidc.post(
        "/v1/ingest",
        json={
            "data": {"content": "hello from oidc"},
            "provenance": {
                "source_id": "oidc-source",
                "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
                "chain_of_custody": ["oidc-source"],
                "classification": 0,
                "model_id": None,
            },
            "purpose": "oidc-testing",
            "subject_id": "subject-oidc",
        },
        headers={"Authorization": f"Bearer {VALID_BEARER_TOKEN}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


# ── Invalid Bearer token ──────────────────────────────────────────────────────

def test_invalid_bearer_returns_401(client_with_oidc: TestClient) -> None:
    r = client_with_oidc.get(
        "/v1/replay/urn:aevum:audit:00000000-0000-7000-8000-000000000001",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401
    body = r.json()
    assert "invalid mock token" in body["detail"]["detail"]


# ── Fallback to API key still works ──────────────────────────────────────────

def test_api_key_still_works_when_oidc_installed(client_with_oidc: TestClient) -> None:
    """Bearer auth does not break existing API key auth."""
    r = client_with_oidc.get("/v1/health")
    assert r.status_code == 200


def test_no_auth_still_401_when_oidc_installed(client_with_oidc: TestClient) -> None:
    r = client_with_oidc.post("/v1/query", json={"purpose": "test", "subject_ids": ["s1"]})
    assert r.status_code == 401


# ── Health endpoint is always unauthenticated ─────────────────────────────────

def test_health_no_auth_returns_200_regardless(client_with_oidc: TestClient) -> None:
    r = client_with_oidc.get("/v1/health")
    assert r.status_code == 200
