# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Tests for AEVUM_MAINTAINER_SIGNING_KEY + restart-safe sigchain restore.

Covers:
  - _event_to_json / _event_from_json round-trip (plain + receipt_cbor case)
  - _MaintenanceStore schema migration for pre-existing on-disk databases
  - The actual bug this feature fixes: with a persistent key, entry_hash and
    valid_from must be identical for the same entry across two server restarts
  - The regression this feature must never introduce: with NO persistent key,
    behavior must be unchanged (unstable across restarts, self-consistent
    within a boot) -- restoring events signed under a since-forgotten
    ephemeral key would otherwise break verify_chain() immediately.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import sqlite3
from typing import TYPE_CHECKING

import pytest
from aevum.core.audit.sigchain import Sigchain
from aevum.core.engine import Engine
from aevum_maintainer.server import (
    _event_from_json,
    _event_to_json,
    _MaintenanceStore,
    create_app,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

if TYPE_CHECKING:
    from aevum.core.audit.event import AuditEvent

_TEST_TOKEN = "test-ingest-token-abc123"


def _make_signing_key() -> str:
    key = Ed25519PrivateKey.generate()
    return base64.b64encode(key.private_bytes_raw()).decode()


# ── _event_to_json / _event_from_json round-trip ─────────────────────────


def _sample_event() -> AuditEvent:
    sc = Sigchain()
    return sc.new_event(event_type="t.sample", payload={"k": "v", "n": 1}, actor="tester")


def test_event_json_round_trip_plain() -> None:
    event = _sample_event()
    assert event.receipt_cbor is None
    restored = _event_from_json(_event_to_json(event))
    assert restored == event


def test_event_json_round_trip_with_receipt_cbor() -> None:
    event = _sample_event()
    with_receipt = dataclasses.replace(event, receipt_cbor=b"\x01\x02\xff\x00binary-cbor-bytes")
    restored = _event_from_json(_event_to_json(with_receipt))
    assert restored == with_receipt
    assert restored.receipt_cbor == b"\x01\x02\xff\x00binary-cbor-bytes"


def test_event_json_serialization_is_json_safe_text() -> None:
    """The serialized form must be a plain JSON string usable in a TEXT column."""
    event = dataclasses.replace(_sample_event(), receipt_cbor=b"\x00\xff")
    serialized = _event_to_json(event)
    assert isinstance(serialized, str)
    json.loads(serialized)  # must not raise


# ── _MaintenanceStore schema migration ────────────────────────────────────


def test_maintenance_store_migrates_pre_existing_schema(tmp_path: pytest.TempPath) -> None:
    """A database created before signed_event_json existed must not crash
    when opened by the new code (CREATE TABLE IF NOT EXISTS is a no-op
    against an already-existing table)."""
    db_file = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE maintenance_entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            principal   TEXT    NOT NULL,
            payload     TEXT    NOT NULL,
            ingested_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute(
        "INSERT INTO maintenance_entries (session_id, action, principal, payload)"
        " VALUES ('s1', 'maintenance.scan', 'ci', '{}')"
    )
    conn.commit()
    conn.close()

    store = _MaintenanceStore(db_file)
    rows = store.all()
    assert len(rows) == 1
    assert rows[0]["signed_event_json"] is None
    store.set_signed_event(row_id=rows[0]["id"], signed_event_json='{"ok": true}')
    assert store.all()[0]["signed_event_json"] == '{"ok": true}'


# ── The actual fix: stability across restarts with a persistent key ──────


def test_persistent_key_entries_are_stable_across_restarts(
    tmp_path: pytest.TempPath, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "maint.db")
    key_b64 = _make_signing_key()
    monkeypatch.setenv("AEVUM_DB_PATH", db_path)
    monkeypatch.setenv("AEVUM_MAINTAINER_SIGNING_KEY", key_b64)

    app1 = create_app()
    client1 = TestClient(app1)
    r1 = client1.get("/v1/replay/example-fund-transfer-review")
    assert r1.status_code == 200
    entries1 = r1.json()["entries"]
    assert len(entries1) == 5

    app2 = create_app()
    client2 = TestClient(app2)
    r2 = client2.get("/v1/replay/example-fund-transfer-review")
    assert r2.status_code == 200
    entries2 = r2.json()["entries"]

    assert len(entries1) == len(entries2)
    for e1, e2 in zip(entries1, entries2, strict=True):
        assert e1["entry_hash"] == e2["entry_hash"]
        assert e1["timestamp"] == e2["timestamp"]
        assert e1["prior_hash"] == e2["prior_hash"]

    sig2 = client2.get("/v1/mcp/verify_sigchain_integrity").json()
    assert sig2["result"]["integrity_ok"] is True


def test_persistent_key_new_entries_survive_restart_and_stay_stable(
    tmp_path: pytest.TempPath, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "maint2.db")
    key_b64 = _make_signing_key()
    monkeypatch.setenv("AEVUM_DB_PATH", db_path)
    monkeypatch.setenv("AEVUM_MAINTAINER_SIGNING_KEY", key_b64)
    monkeypatch.setenv("MAINTENANCE_INGEST_TOKEN", _TEST_TOKEN)

    app1 = create_app()
    client1 = TestClient(app1)
    res = client1.post(
        "/v1/maintenance/ingest",
        json={
            "session_id": "restart-session",
            "entries": [
                {
                    "action": "maintenance.scan",
                    "resource": "x",
                    "principal": "ci",
                    "payload": {"k": 1},
                },
            ],
        },
        headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
    )
    assert res.status_code == 201

    r1 = client1.get("/v1/replay/restart-session").json()
    assert r1["entry_count"] == 1
    first_pass_entry = r1["entries"][0]

    # Restart: the newly-ingested row has no signed_event_json yet (it was
    # written by the live /v1/maintenance/ingest call, not by the replay
    # loop), so it gets signed once on this boot and then must be frozen.
    app2 = create_app()
    client2 = TestClient(app2)
    r2 = client2.get("/v1/replay/restart-session").json()
    assert r2["entry_count"] == 1
    second_pass_entry = r2["entries"][0]
    assert second_pass_entry["timestamp"] == first_pass_entry["timestamp"]

    # A third boot must reuse the now-persisted signed_event_json unchanged.
    app3 = create_app()
    client3 = TestClient(app3)
    r3 = client3.get("/v1/replay/restart-session").json()
    third_pass_entry = r3["entries"][0]
    assert third_pass_entry["entry_hash"] == second_pass_entry["entry_hash"]
    assert third_pass_entry["timestamp"] == second_pass_entry["timestamp"]


# ── Regression guard: no persistent key must behave exactly as before ────


def test_no_signing_key_behavior_is_unchanged(
    tmp_path: pytest.TempPath, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "nokey.db")
    monkeypatch.delenv("AEVUM_MAINTAINER_SIGNING_KEY", raising=False)
    monkeypatch.setenv("AEVUM_DB_PATH", db_path)

    app1 = create_app()
    client1 = TestClient(app1)
    r1 = client1.get("/v1/replay/example-fund-transfer-review").json()

    app2 = create_app()
    client2 = TestClient(app2)
    r2 = client2.get("/v1/replay/example-fund-transfer-review").json()

    # Without a persistent key, each boot gets a brand-new ephemeral key and
    # re-signs everything fresh -- entries must NOT be identical across
    # restarts (matching the long-standing, unfixed-without-a-key behavior),
    # and each boot's own chain must still verify internally.
    assert r1["entries"][0]["entry_hash"] != r2["entries"][0]["entry_hash"]

    sig1 = client1.get("/v1/mcp/verify_sigchain_integrity").json()
    sig2 = client2.get("/v1/mcp/verify_sigchain_integrity").json()
    assert sig1["result"]["integrity_ok"] is True
    assert sig2["result"]["integrity_ok"] is True


def test_invalid_signing_key_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPath,
) -> None:
    monkeypatch.setenv("AEVUM_DB_PATH", str(tmp_path / "bad.db"))
    monkeypatch.setenv("AEVUM_MAINTAINER_SIGNING_KEY", "not-valid-base64-key-material!!")
    with pytest.raises(ValueError):
        create_app()


def test_engine_injected_ignores_signing_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """When an Engine is injected (tests), persistence/signing-key wiring
    must be skipped entirely -- this is the existing test-isolation contract."""
    monkeypatch.setenv("AEVUM_MAINTAINER_SIGNING_KEY", _make_signing_key())
    engine = Engine()
    app = create_app(engine=engine)
    client = TestClient(app, raise_server_exceptions=False)
    res = client.get("/health")
    assert res.status_code == 200
