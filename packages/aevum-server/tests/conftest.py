"""
Shared test fixtures for aevum-server tests.
"""

from __future__ import annotations

import pytest
from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine
from fastapi.testclient import TestClient

from aevum.server.app import create_app
from aevum.server.core.config import Settings

TEST_API_KEY = "test-api-key-for-ci"


def _make_settings() -> Settings:
    return Settings(api_key=TEST_API_KEY, otel_enabled=False)


def _make_engine_with_consent() -> Engine:
    engine = Engine()
    engine.add_consent_grant(ConsentGrant(
        grant_id="test-grant-1",
        subject_id="subject-1",
        grantee_id=TEST_API_KEY,  # actor = api key value
        operations=["ingest", "query", "replay", "export"],
        purpose="integration-testing",
        classification_max=3,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))
    return engine


@pytest.fixture
def client() -> TestClient:
    """Client with a fresh engine that has no consent grants."""
    app = create_app(engine=Engine(), settings=_make_settings())
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def authed_client() -> TestClient:
    """Client with consent grants and auth header pre-set."""
    app = create_app(engine=_make_engine_with_consent(), settings=_make_settings())
    return TestClient(
        app,
        headers={"X-Aevum-Key": TEST_API_KEY},
        raise_server_exceptions=False,
    )


@pytest.fixture
def valid_ingest_body() -> dict:
    return {
        "data": {"content": "test datum"},
        "provenance": {
            "source_id": "test-source",
            "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
            "chain_of_custody": ["test-source"],
            "classification": 0,
            "model_id": None,
        },
        "purpose": "integration-testing",
        "subject_id": "subject-1",
    }
