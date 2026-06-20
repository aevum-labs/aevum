# SPDX-License-Identifier: Apache-2.0
"""CommitmentKeyStore tests (S-17/R10: every public endpoint has a test).

P2-IDENTITY-V2 (DD1, DD5, DD6, DD8, spec aevum-signing-v2.md).
"""
from __future__ import annotations

import inspect
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.event import compute_principal_commitment
from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain


def make_ledger() -> InMemoryLedger:
    return InMemoryLedger(Sigchain())


class TestCreateKey:
    def test_create_key_returns_id(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        assert isinstance(key_id, str)
        assert len(key_id) > 0

    def test_create_key_autogenerates_id_when_not_given(self) -> None:
        store = CommitmentKeyStore()
        id_a = store.create_key(scope="dep-1")
        id_b = store.create_key(scope="dep-1")
        assert id_a != id_b

    def test_create_key_honors_explicit_id(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1", commitment_key_id="my-key-id")
        assert key_id == "my-key-id"

    def test_create_key_with_explicit_bytes(self) -> None:
        store = CommitmentKeyStore()
        raw = os.urandom(32)
        key_id = store.create_key(scope="dep-1", key_bytes=raw)
        assert store.get_key(key_id) == raw

    def test_create_key_rejects_wrong_length_bytes(self) -> None:
        store = CommitmentKeyStore()
        with pytest.raises(ValueError):
            store.create_key(scope="dep-1", key_bytes=b"too-short")

    def test_create_key_resolution_priority_arg_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Constructor-arg key_bytes overrides AEVUM_COMMITMENT_KEY env var."""
        env_key = os.urandom(32)
        arg_key = os.urandom(32)
        monkeypatch.setenv("AEVUM_COMMITMENT_KEY", env_key.hex())
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1", key_bytes=arg_key)
        assert store.get_key(key_id) == arg_key
        assert store.get_key(key_id) != env_key

    def test_create_key_resolution_priority_env_over_autogen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        env_key = os.urandom(32)
        monkeypatch.setenv("AEVUM_COMMITMENT_KEY", env_key.hex())
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        assert store.get_key(key_id) == env_key

    def test_create_key_autogen_when_no_arg_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEVUM_COMMITMENT_KEY", raising=False)
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        key = store.get_key(key_id)
        assert key is not None
        assert len(key) == 32

    def test_multiple_keys_independent(self) -> None:
        store = CommitmentKeyStore()
        id_a = store.create_key(scope="dep-a")
        id_b = store.create_key(scope="dep-b")
        assert store.get_key(id_a) != store.get_key(id_b)
        assert store.scope_for(id_a) == "dep-a"
        assert store.scope_for(id_b) == "dep-b"


class TestGetKeyAndScope:
    def test_get_key_returns_none_for_unknown_id(self) -> None:
        store = CommitmentKeyStore()
        assert store.get_key("never-existed") is None

    def test_scope_for_returns_none_for_unknown_id(self) -> None:
        store = CommitmentKeyStore()
        assert store.scope_for("never-existed") is None

    def test_scope_for_returns_creation_scope(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="demo-deployment")
        assert store.scope_for(key_id) == "demo-deployment"


class TestCommitmentFor:
    def test_commitment_for_matches_compute_principal_commitment(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        key = store.get_key(key_id)
        assert key is not None
        expected = compute_principal_commitment(key, "urn:test:oidc:sub:alice")
        assert store.commitment_for(key_id, "urn:test:oidc:sub:alice") == expected

    def test_commitment_for_returns_none_when_key_absent(self) -> None:
        store = CommitmentKeyStore()
        assert store.commitment_for("never-existed", "urn:test:oidc:sub:alice") is None

    def test_commitment_for_distinguishes_principals(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        c1 = store.commitment_for(key_id, "urn:test:oidc:sub:alice")
        c2 = store.commitment_for(key_id, "urn:test:oidc:sub:bob")
        assert c1 != c2


class TestDestroy:
    def test_destroy_makes_key_unrecoverable(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        ledger = make_ledger()
        store.destroy(key_id, ledger=ledger, actor="admin")
        assert store.get_key(key_id) is None

    def test_destroy_after_destroy_indistinguishable_from_never_existed(self) -> None:
        """DD5: callers cannot distinguish 'destroyed' from 'never existed' —
        both mean the commitment can no longer be confirmed."""
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        ledger = make_ledger()
        store.destroy(key_id, ledger=ledger, actor="admin")
        assert store.get_key(key_id) is None
        assert store.scope_for(key_id) is None
        assert store.commitment_for(key_id, "urn:test:oidc:sub:alice") is None

    def test_destroy_appends_auditable_event(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        ledger = make_ledger()
        event = store.destroy(key_id, ledger=ledger, actor="admin")
        assert event.event_type == "commitment_key.destroyed"
        assert event.payload["commitment_key_id"] == key_id
        assert event.payload["scope"] == "dep-1"
        assert event.actor == "admin"

    def test_destroy_event_is_appended_to_the_given_ledger(self) -> None:
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="dep-1")
        ledger = make_ledger()
        assert ledger.count() == 0
        store.destroy(key_id, ledger=ledger, actor="admin")
        assert ledger.count() == 1
        assert ledger.all_events()[0].event_type == "commitment_key.destroyed"

    def test_destroy_does_not_remove_other_keys(self) -> None:
        store = CommitmentKeyStore()
        id_a = store.create_key(scope="dep-a")
        id_b = store.create_key(scope="dep-b")
        ledger = make_ledger()
        store.destroy(id_a, ledger=ledger, actor="admin")
        assert store.get_key(id_a) is None
        assert store.get_key(id_b) is not None

    def test_commitment_key_destroyed_is_a_reserved_event_type(self) -> None:
        """The commit() function (REMEMBER) must reject app code forging this
        kernel-asserted event type — see commit.py _RESERVED_PREFIXES."""
        from aevum.core.functions.commit import _RESERVED_PREFIXES
        assert "commitment_key.destroyed".startswith(_RESERVED_PREFIXES)


class TestPersistence:
    def test_persistent_store_survives_reopen(self, tmp_path: Path) -> None:
        db_path = tmp_path / "commitment_keys.db"
        store = CommitmentKeyStore(db_path)
        key_id = store.create_key(scope="dep-1")
        key = store.get_key(key_id)
        store.close()

        reopened = CommitmentKeyStore(db_path)
        assert reopened.get_key(key_id) == key
        assert reopened.scope_for(key_id) == "dep-1"
        reopened.close()

    def test_default_constructor_is_in_memory(self) -> None:
        store = CommitmentKeyStore()
        assert store._db_path == ":memory:"


class TestSecureErasure:
    """GREEN: destroy() must make the key bytes unrecoverable from the raw db
    file, not just unindexed (PRAGMA secure_delete=ON) — mirrors
    test_phase3_consent.py::TestSecureErasure for ConsentLedger's DEK vault."""

    def test_init_schema_source_sets_secure_delete(self) -> None:
        source = inspect.getsource(CommitmentKeyStore._init_schema)
        assert "secure_delete=on" in source.lower().replace(" ", "")

    def test_store_enables_secure_delete(self, tmp_path: Path) -> None:
        store = CommitmentKeyStore(tmp_path / "pragma_check.db")
        assert store._conn.execute("PRAGMA secure_delete;").fetchone()[0] == 1
        store.close()

    def test_destroy_removes_key_bytes_from_raw_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "secure_erasure.db"
        store = CommitmentKeyStore(db_path)
        marker = (b"SECDEL_" + os.urandom(8).hex().encode())[:32].ljust(32, b"\0")
        key_id = store.create_key(scope="dep-1", key_bytes=marker)

        # Sanity check: the marker is actually on disk before destroy.
        assert marker in db_path.read_bytes()

        ledger = make_ledger()
        store.destroy(key_id, ledger=ledger, actor="admin")
        store.close()

        assert marker not in db_path.read_bytes()

    def test_without_secure_delete_marker_can_survive_deletion(self, tmp_path: Path) -> None:
        """Baseline proving the pragma is load-bearing: on a connection with
        secure_delete explicitly OFF, the same insert/delete/commit sequence
        leaves the key bytes recoverable on disk."""
        db_path = tmp_path / "secure_erasure_baseline.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA secure_delete=OFF;")
        conn.executescript("""
            CREATE TABLE commitment_keys (
                commitment_key_id  TEXT PRIMARY KEY,
                scope               TEXT NOT NULL,
                key_bytes           BLOB NOT NULL,
                created_at          TEXT NOT NULL
            );
        """)
        conn.commit()
        marker = b"BASELINE_MARKER_" + os.urandom(8).hex().encode()
        conn.execute(
            "INSERT INTO commitment_keys VALUES (?, ?, ?, ?)",
            ("baseline_key", "dep-1", marker, datetime.now(UTC).isoformat()),
        )
        conn.commit()
        conn.execute("DELETE FROM commitment_keys WHERE commitment_key_id = ?", ("baseline_key",))
        conn.commit()
        conn.close()
        assert marker in db_path.read_bytes()
