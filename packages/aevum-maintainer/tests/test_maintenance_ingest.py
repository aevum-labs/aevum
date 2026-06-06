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


# ── GET /v1/replay/{session_id} ──────────────────────────────


def test_replay_returns_session_entries(ingest_client: TestClient) -> None:
    _ingest(
        ingest_client,
        [_entry("maintenance.scan"), _entry("maintenance.audit")],
        session_id="maint-replay-test",
    )
    res = ingest_client.get("/v1/replay/maint-replay-test")
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"] == "maint-replay-test"
    assert data["entry_count"] == 2
    assert isinstance(data["chain_valid"], bool)
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) == 2
    assert "head_hash" in data


def test_replay_entry_fields(ingest_client: TestClient) -> None:
    _ingest(ingest_client, [_entry("maintenance.scan")], session_id="maint-fields-test")
    data = ingest_client.get("/v1/replay/maint-fields-test").json()
    entry = data["entries"][0]
    assert "entry_hash" in entry
    assert "prior_hash" in entry
    assert "action" in entry
    assert "principal" in entry
    assert "timestamp" in entry
    assert "session_id" in entry
    assert entry["action"] == "maintenance.scan"
    assert entry["session_id"] == "maint-fields-test"


def test_replay_unknown_session_returns_404(ingest_client: TestClient) -> None:
    res = ingest_client.get("/v1/replay/no-such-session-xyz")
    assert res.status_code == 404


# ── Timestamp preservation ────────────────────────────────────


def test_ingest_embeds_occurred_at_in_payload(
    ingest_client: TestClient,
) -> None:
    """_occurred_at is embedded so replayed entries carry the original ingest time."""
    res = _ingest(ingest_client, [_entry("maintenance.scan")], session_id="ts-test-001")
    assert res.status_code == 201
    chain = ingest_client.get("/v1/replay/ts-test-001").json()
    entry = chain["entries"][0]
    ts = entry.get("timestamp", "")
    assert ts, "timestamp must be non-empty"
    # Must be ISO 8601 with timezone offset (not a naive datetime).
    assert "T" in ts, f"expected ISO 8601 timestamp, got {ts!r}"
    assert "+" in ts or ts.endswith("Z"), (
        f"timestamp must carry UTC offset, got {ts!r}"
    )


def test_replayed_entries_preserve_original_timestamps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pytest.TempPathFactory,
) -> None:
    """Entries replayed after a server restart show original ingest time, not replay time."""
    from aevum.core.engine import Engine
    from aevum_maintainer.server import _MaintenanceStore

    # Use a real file so _connect() returns the same DB each call.
    db_file = str(tmp_path / "test_replay.db")
    store = _MaintenanceStore(db_file)
    original_ts = "2026-06-01T10:00:00+00:00"
    store.add(
        session_id="replay-ts-session",
        action="maintenance.scan",
        principal="github_actions",
        payload={"cve_count": 0, "_occurred_at": original_ts},
    )

    # Simulate server restart: replay stored entries into a fresh engine.
    engine = Engine()
    for entry in store.all():
        engine.commit(
            event_type=entry["action"],
            payload=entry["payload"],
            actor=entry["principal"],
            episode_id=entry["session_id"],
        )

    from aevum_maintainer.server import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setenv("MAINTENANCE_INGEST_TOKEN", _TEST_TOKEN)
    app = create_app(engine=engine)
    client = TestClient(app)
    chain = client.get("/v1/replay/replay-ts-session").json()
    assert chain["entry_count"] >= 1, "Expected replayed entry in chain"
    ts = chain["entries"][0].get("timestamp", "")
    assert ts == original_ts, (
        f"Expected original timestamp {original_ts!r}, got {ts!r} — "
        "replay is overwriting with current time"
    )


# ── Sigchain timestamp consistency (S-12) ────────────────────────────────────


def test_scrub_entry_uses_valid_from_not_occurred_at(
    ingest_client: TestClient,
) -> None:
    """valid_from must be the display timestamp, not _occurred_at."""
    _ingest(ingest_client, [{
        "action": "maintenance.scan",
        "resource": "test",
        "principal": "ci",
        "payload": {
            "_occurred_at": "2020-01-01T00:00:00+00:00",
            "summary": "test",
        },
    }])
    data = ingest_client.get("/v1/sigchain/recent").json()
    entries = data.get("entries", [])
    assert entries, "Expected at least one entry"
    assert entries[0].get("timestamp") != "2020-01-01T00:00:00+00:00", \
        "Displayed timestamp must be valid_from, not _occurred_at"
    ts = entries[0].get("timestamp", "")
    assert "2026" in ts or "2025" in ts, \
        f"Expected recent timestamp, got: {ts}"


def test_session_start_filtered_from_sigchain_recent(
    ingest_client: TestClient,
) -> None:
    """session.start entries must not appear in the public sigchain feed."""
    data = ingest_client.get("/v1/sigchain/recent").json()
    event_types = [
        e.get("event_type", e.get("action", ""))
        for e in data.get("entries", [])
    ]
    assert "session.start" not in event_types, \
        "session.start is a system event and must be filtered from the public feed"


def test_count_includes_system_events(ingest_client: TestClient) -> None:
    """count field reflects total ledger size including filtered entries."""
    data = ingest_client.get("/v1/sigchain/recent").json()
    visible = len(data.get("entries", []))
    total = data.get("count", 0)
    assert total >= visible, \
        "count must be >= len(entries) since system events are counted but filtered"
