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


def test_scrub_entry_uses_occurred_at_after_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pytest.TempPath,
) -> None:
    """After server restart, display timestamp is _occurred_at (original ingest time).

    Simulates the restart scenario: entries stored in SQLite with an old _occurred_at
    are replayed into a fresh engine. The public sigchain feed must show _occurred_at,
    not the replay-time valid_from (which would make all timestamps identical).
    """
    from aevum_maintainer.server import _MaintenanceStore

    db_file = str(tmp_path / "test_ts.db")
    store = _MaintenanceStore(db_file)
    original_ts = "2020-01-01T00:00:00+00:00"
    store.add(
        session_id="ts-restart-test",
        action="maintenance.scan",
        principal="ci",
        payload={"_occurred_at": original_ts, "summary": "test"},
    )

    from aevum.core.engine import Engine
    engine = Engine()
    for entry in store.all():
        engine.commit(
            event_type=entry["action"],
            payload=entry["payload"],
            actor=entry["principal"],
            episode_id=entry["session_id"],
        )

    monkeypatch.setenv("MAINTENANCE_INGEST_TOKEN", _TEST_TOKEN)
    app = create_app(engine=engine)
    client = TestClient(app)
    data = client.get("/v1/sigchain/recent").json()
    entries = data.get("entries", [])
    scan_entries = [e for e in entries if e.get("event_type") == "maintenance.scan"]
    assert scan_entries, "Expected maintenance.scan entry in sigchain/recent"
    assert scan_entries[0].get("timestamp") == original_ts, (
        f"Display timestamp must be _occurred_at ({original_ts!r}), "
        f"got {scan_entries[0].get('timestamp')!r} — "
        "valid_from would make all restarted entries show identical timestamps"
    )


def test_sigchain_recent_includes_session_start(
    ingest_client: TestClient,
) -> None:
    """session.start must appear in the public sigchain feed."""
    data = ingest_client.get("/v1/sigchain/recent").json()
    event_types = [e.get("event_type", "") for e in data.get("entries", [])]
    assert "session.start" in event_types, (
        "session.start must be visible in the public feed"
    )


def test_sigchain_recent_chain_order_descending(
    ingest_client: TestClient,
) -> None:
    """Entries must be ordered by chain sequence descending (most recently committed first).

    Ingests scan then audit; feed must return audit first (higher sequence),
    scan second, session.start last (sequence 1, committed at startup).
    """
    _ingest(ingest_client, [_entry("maintenance.scan")], session_id="order-a")
    _ingest(ingest_client, [_entry("maintenance.audit")], session_id="order-b")
    data = ingest_client.get("/v1/sigchain/recent").json()
    event_types = [e.get("event_type", "") for e in data.get("entries", [])]
    audit_idx = event_types.index("maintenance.audit") if "maintenance.audit" in event_types else -1
    scan_idx = event_types.index("maintenance.scan") if "maintenance.scan" in event_types else -1
    start_idx = event_types.index("session.start") if "session.start" in event_types else -1
    assert audit_idx != -1 and scan_idx != -1 and start_idx != -1, (
        f"Expected all three event types; got {event_types}"
    )
    assert audit_idx < scan_idx < start_idx, (
        f"Expected audit({audit_idx}) < scan({scan_idx}) < session.start({start_idx}); "
        f"chain order must be descending (most recently committed first)"
    )


def test_count_equals_total_ledger_size(ingest_client: TestClient) -> None:
    """count field reflects total ledger size (all entries including session.start)."""
    _ingest(ingest_client, [_entry("maintenance.scan")])
    data = ingest_client.get("/v1/sigchain/recent").json()
    total = data.get("count", 0)
    visible = len(data.get("entries", []))
    assert total >= visible, "count must be >= len(entries)"
    assert total >= 2, "count must include at least session.start + the ingested entry"


# ── GET /v1/sessions — governance session labeling ────────────


def test_sessions_labels_pr_merged_session_as_governance(
    ingest_client: TestClient,
) -> None:
    """governance-ingest.yml writes session_id='pr-<N>'; must render as Governance."""
    _ingest(
        ingest_client,
        [_entry("governance.pr_merged")],
        session_id="pr-347",
    )
    data = ingest_client.get("/v1/sessions").json()
    sessions = {s["session_id"]: s for s in data["sessions"]}
    assert "pr-347" in sessions
    assert sessions["pr-347"]["session_type"] == "governance"
    assert "Governance" in sessions["pr-347"]["label"]


def test_sessions_labels_release_session_as_governance(
    ingest_client: TestClient,
) -> None:
    """release.yml writes session_id='release-<tag>'; must render as Governance/Release."""
    _ingest(
        ingest_client,
        [_entry("release.published")],
        session_id="release-v0.8.0",
    )
    data = ingest_client.get("/v1/sessions").json()
    sessions = {s["session_id"]: s for s in data["sessions"]}
    assert "release-v0.8.0" in sessions
    assert sessions["release-v0.8.0"]["session_type"] == "governance"
    assert "Release" in sessions["release-v0.8.0"]["label"]


def test_ingest_auth_uses_constant_time_comparison() -> None:
    """Both bearer-token checks (OIDC scan + maintenance ingest) must use
    hmac.compare_digest — never a raw == / != on the secret. Timing-safe by
    construction; this guards against regression to a plain comparison."""
    from pathlib import Path

    import aevum_maintainer.server as server_mod

    source = Path(server_mod.__file__).read_text()
    assert source.count("hmac.compare_digest(") >= 2, (
        "expected >=2 hmac.compare_digest call sites (OIDC scan + maintenance ingest)"
    )
    assert "!= expected_token" not in source, (
        "raw '!= expected_token' found — use hmac.compare_digest (timing-safe)"
    )
    assert "== expected_token" not in source, (
        "raw '== expected_token' found — use hmac.compare_digest (timing-safe)"
    )
