# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for sandbox routes — POST /sandbox/scan,
/sandbox/consent, /sandbox/execute, GET /sandbox/sigchain."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from fastapi.testclient import TestClient

if TYPE_CHECKING:
    from aevum.core.engine import Engine
    from pytest import MonkeyPatch


@pytest.fixture
def app_bundle(monkeypatch: MonkeyPatch) -> tuple[TestClient, Engine]:
    """Returns (TestClient, Engine) so tests can inspect production state directly."""
    monkeypatch.setenv("AEVUM_DB_PATH", ":memory:")
    import aevum_maintainer.sandbox as sb_module
    sb_module._sandboxes.clear()
    from aevum.core.engine import Engine
    from aevum_maintainer.server import create_app
    eng = Engine()
    return TestClient(create_app(engine=eng)), eng


@pytest.fixture
def client(app_bundle: tuple[TestClient, Engine]) -> TestClient:
    return app_bundle[0]


ACTOR = "demo-agent"
HEADERS: dict[str, str] = {"X-Demo-Actor": ACTOR}


def test_sandbox_scan_returns_200(client: TestClient) -> None:
    res = client.post(
        "/sandbox/scan",
        json={"host_id": "host-42", "scan_type": "diagnostic"},
        headers=HEADERS,
    )
    assert res.status_code == 200, res.text
    data: dict[str, Any] = res.json()
    assert "task_id" in data


def test_sandbox_consent_returns_200(client: TestClient) -> None:
    scan = client.post(
        "/sandbox/scan",
        json={"host_id": "host-42", "scan_type": "diagnostic"},
        headers=HEADERS,
    )
    task_id: str = scan.json()["task_id"]
    res = client.post(
        "/sandbox/consent",
        json={"task_id": task_id, "decision": "approve"},
        headers=HEADERS,
    )
    assert res.status_code == 200, res.text
    data: dict[str, Any] = res.json()
    assert "consent_token" in data


def test_sandbox_execute_returns_200(client: TestClient) -> None:
    scan = client.post(
        "/sandbox/scan",
        json={"host_id": "host-42", "scan_type": "diagnostic"},
        headers=HEADERS,
    )
    task_id: str = scan.json()["task_id"]
    consent = client.post(
        "/sandbox/consent",
        json={"task_id": task_id, "decision": "approve"},
        headers=HEADERS,
    )
    token: str = consent.json()["consent_token"]
    res = client.post(
        "/sandbox/execute",
        json={"task_id": task_id, "consent_token": token},
        headers=HEADERS,
    )
    assert res.status_code == 200, res.text
    data: dict[str, Any] = res.json()
    assert "sigchain_head" in data


def test_sandbox_sigchain_returns_200(client: TestClient) -> None:
    res = client.get("/sandbox/sigchain", headers=HEADERS)
    assert res.status_code == 200, res.text
    data: dict[str, Any] = res.json()
    assert "entries" in data or "head_hash" in data


def test_sandbox_reset_clears_session(client: TestClient) -> None:
    client.post(
        "/sandbox/scan",
        json={"host_id": "host-42", "scan_type": "diagnostic"},
        headers=HEADERS,
    )
    res = client.post("/sandbox/reset", headers=HEADERS)
    assert res.status_code == 200, res.text
    data: dict[str, Any] = res.json()
    assert data.get("reset") is True


def test_sandbox_isolated_from_production(
    app_bundle: tuple[TestClient, Engine],
) -> None:
    """A7: sandbox actions must not appear in production sigchain."""
    tc, engine = app_bundle
    tc.post(
        "/sandbox/scan",
        json={"host_id": "host-42", "scan_type": "diagnostic"},
        headers=HEADERS,
    )
    prod_hashes = {e.get("payload_hash", "") for e in engine.get_ledger_entries()}
    sandbox_sig = tc.get("/sandbox/sigchain", headers=HEADERS)
    assert sandbox_sig.status_code == 200
    sandbox_hashes = [
        e.get("sigchain_entry_hash", "")
        for e in sandbox_sig.json().get("entries", [])
    ]
    for h in sandbox_hashes:
        assert h not in prod_hashes, "Sandbox entry leaked into production sigchain"


def test_sandbox_consent_not_found(client: TestClient) -> None:
    res = client.post(
        "/sandbox/consent",
        json={"task_id": "tsk_nonexistent", "decision": "approve"},
        headers=HEADERS,
    )
    assert res.status_code == 404


def test_sandbox_execute_without_consent_rejected(client: TestClient) -> None:
    scan = client.post(
        "/sandbox/scan",
        json={"host_id": "host-42", "scan_type": "diagnostic"},
        headers=HEADERS,
    )
    task_id: str = scan.json()["task_id"]
    res = client.post(
        "/sandbox/execute",
        json={"task_id": task_id, "consent_token": "bad_token"},
        headers=HEADERS,
    )
    assert res.status_code == 409
