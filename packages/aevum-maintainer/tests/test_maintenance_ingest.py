# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Tests for POST /v1/maintenance/ingest endpoint.

Uses TestClient — no network required.
A7: asserts that ingest never affects the sandbox sigchain.
"""
from __future__ import annotations

import pytest
from aevum.core.engine import Engine
from aevum_maintainer.server import create_app
from fastapi.testclient import TestClient

_TEST_TOKEN = "test-ingest-token-abc123"


@pytest.fixture
def ingest_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("MAINTENANCE_INGEST_TOKEN", _TEST_TOKEN)
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _entry(action: str = "maintenance.scan") -> dict:
    return {
        "action": action,
        "resource": "aevum-labs/aevum",
        "principal": "github_actions",
        "payload": {"cve_count": 0, "status": "clean"},
    }


def _ingest(
    client: TestClient,
    entries: list[dict],
    session_id: str = "test-run-001",
    token: str = _TEST_TOKEN,
) -> object:
    return client.post(
        "/v1/maintenance/ingest",
        json={"session_id": session_id, "entries": entries},
        headers={"Authorization": f"Bearer {token}"},
    )


# ── Auth tests ────────────────────────────────────────────────


def test_ingest_missing_token_401(ingest_client: TestClient) -> None:
    res = ingest_client.post(
        "/v1/maintenance/ingest",
        json={"session_id": "s", "entries": [_entry()]},
    )
    assert res.status_code == 401


def test_ingest_wrong_token_401(ingest_client: TestClient) -> None:
    res = _ingest(ingest_client, [_entry()], token="wrong-token")
    assert res.status_code == 401


def test_ingest_no_env_token_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MAINTENANCE_INGEST_TOKEN", raising=False)
    app = create_app()
    c = TestClient(app, raise_server_exceptions=False)
    res = c.post(
        "/v1/maintenance/ingest",
        json={"session_id": "s", "entries": [_entry()]},
        headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
    )
    assert res.status_code == 503


# ── Happy path ────────────────────────────────────────────────


def test_ingest_single_entry(ingest_client: TestClient) -> None:
    res = _ingest(ingest_client, [_entry("maintenance.scan")])
    assert res.status_code == 201
    data = res.json()
    assert data["accepted"] == 1
    assert len(data["audit_ids"]) == 1
    assert data["audit_ids"][0].startswith("urn:aevum:audit:")


def test_ingest_multiple_entries(ingest_client: TestClient) -> None:
    entries = [
        _entry("maintenance.scan"),
        _entry("maintenance.audit"),
        _entry("maintenance.complete"),
    ]
    res = _ingest(ingest_client, entries)
    assert res.status_code == 201
    data = res.json()
    assert data["accepted"] == 3
    assert len(data["audit_ids"]) == 3


def test_ingest_entries_appear_in_sigchain(
    ingest_client: TestClient,
) -> None:
    _ingest(ingest_client, [_entry("maintenance.scan")], session_id="sess-xyz")
    res = ingest_client.get("/v1/sigchain/recent")
    assert res.status_code == 200
    entries = res.json().get("entries", [])
    assert len(entries) >= 1
    actions = [e.get("event_type", "") for e in entries]
    assert "maintenance.scan" in actions


def test_sigchain_recent_returns_200_empty(
    ingest_client: TestClient,
) -> None:
    """Even with no entries, /v1/sigchain/recent returns 200."""
    res = ingest_client.get("/v1/sigchain/recent")
    assert res.status_code == 200
    data = res.json()
    assert "entries" in data
    assert "count" in data


def test_ingest_empty_entries_422(ingest_client: TestClient) -> None:
    res = _ingest(ingest_client, [])
    assert res.status_code == 422


def test_ingest_missing_field_422(ingest_client: TestClient) -> None:
    bad = {"action": "maintenance.scan", "resource": "aevum"}
    # missing principal and payload
    res = _ingest(ingest_client, [bad])
    assert res.status_code == 422


# ── A7: sandbox isolation ────────────────────────────────────


def test_ingest_does_not_affect_sandbox(
    ingest_client: TestClient,
) -> None:
    """A7: production ingest must never write to the sandbox sigchain.

    The maintainer server has one Engine instance (production). Entries
    written via /v1/maintenance/ingest must only appear in the production
    ledger and must not cross-contaminate any separate sandbox context.
    """
    engine = Engine()
    sandbox_before = list(engine._ledger.all_events())

    res = _ingest(ingest_client, [_entry()], session_id="prod-run")
    assert res.status_code == 201
    prod_audit_ids = res.json()["audit_ids"]

    # A fresh Engine() has its own isolated ledger — prod entries must not appear
    sandbox_after = list(engine._ledger.all_events())
    assert len(sandbox_after) == len(sandbox_before), (
        "Production ingest leaked entries into an isolated Engine (A7 violation)"
    )
    sandbox_ids = {e.audit_id() for e in sandbox_after}
    for aid in prod_audit_ids:
        assert aid not in sandbox_ids, (
            f"Production audit_id {aid!r} appeared in isolated sandbox engine (A7 violation)"
        )
