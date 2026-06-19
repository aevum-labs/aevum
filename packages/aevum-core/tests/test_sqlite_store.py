# SPDX-License-Identifier: Apache-2.0
"""Tests for SqliteReceiptStore, ReceiptStore protocol, and escalation logic."""

from __future__ import annotations

import hashlib
import os
import time

import pytest

from aevum.core.escalation import escalate_if_triggered, should_escalate
from aevum.core.sqlite_store import SqliteReceiptStore
from aevum.core.store import (
    NullReceiptStore,
    ReceiptNotFoundError,
    ReceiptStore,
)

# ── SqliteReceiptStore basic CRUD ─────────────────────────────────────────────

class TestSqliteReceiptStore:
    def _store(self) -> SqliteReceiptStore:
        return SqliteReceiptStore(db_path=":memory:")

    def test_put_and_get_roundtrip(self) -> None:
        store = self._store()
        blob = b"x" * 400
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob, entry_hash="abc123")
        assert store.get(h) == blob

    def test_get_missing_returns_none(self) -> None:
        store = self._store()
        assert store.get("nonexistent" * 4) is None

    def test_put_idempotent(self) -> None:
        store = self._store()
        blob = b"idempotent"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        store.put(h, blob)  # second put must not error
        assert store.get(h) == blob

    def test_list_hashes_returns_stored(self) -> None:
        store = self._store()
        blob = b"list_test"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        assert h in store.list_hashes()

    def test_list_hashes_tier_filter(self) -> None:
        store = self._store()
        blob = b"tier_filter"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob, tier="operational")
        assert h in store.list_hashes(tier="operational")
        assert h not in store.list_hashes(tier="crash_protected")
        assert h not in store.list_hashes(tier="long_term")

    def test_list_hashes_pagination(self) -> None:
        store = self._store()
        hashes = []
        for i in range(5):
            blob = f"page_{i}".encode()
            h = hashlib.sha3_256(blob).hexdigest()
            store.put(h, blob)
            hashes.append(h)
        hashes.sort()
        # First page
        page1 = store.list_hashes(limit=3)
        assert len(page1) == 3
        # Second page using cursor
        page2 = store.list_hashes(after=page1[-1], limit=10)
        assert all(h > page1[-1] for h in page2)


class TestSqliteReceiptStoreLock:
    def test_lock_escalates_to_crash_protected(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"lockme"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        store.lock(h)
        info = store.get_receipt_info(h)
        assert info is not None
        assert info["locked"] is True
        assert info["tier"] == "crash_protected"

    def test_lock_idempotent(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"locktwice"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        store.lock(h)
        store.lock(h)  # must not raise
        info = store.get_receipt_info(h)
        assert info is not None
        assert info["locked"] is True

    def test_lock_raises_for_missing(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        with pytest.raises(ReceiptNotFoundError):
            store.lock("nonexistent" * 4)

    def test_get_receipt_info_none_for_missing(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        assert store.get_receipt_info("nothere") is None


class TestSqliteReceiptStoreAmbient:
    def test_put_and_get_ambient(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        store.put_ambient("snap-001", b"ambient_blob", "sess-001", "SESSION_START")
        assert store.get_ambient("snap-001") == b"ambient_blob"

    def test_get_ambient_missing_returns_none(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        assert store.get_ambient("does_not_exist") is None

    def test_put_ambient_idempotent(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        store.put_ambient("snap-x", b"data", "sess-1", "PERIODIC")
        store.put_ambient("snap-x", b"data2", "sess-1", "PERIODIC")  # must not error
        # First write wins (INSERT OR IGNORE)
        assert store.get_ambient("snap-x") == b"data"


class TestSqliteReceiptStoreRotation:
    def test_rotate_operational_promotes_old(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"old_receipt"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        # Force stored_at to be 50 hours ago
        store._conn.execute(
            "UPDATE receipts SET stored_at=? WHERE receipt_hash=?",
            (time.time() - 50 * 3600, h),
        )
        store._conn.commit()
        rotated = store.rotate_operational(hours=48)
        assert rotated == 1
        assert h in store.list_hashes(tier="long_term")
        assert h not in store.list_hashes(tier="operational")

    def test_rotate_skips_recent(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"fresh_receipt"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        rotated = store.rotate_operational(hours=48)
        assert rotated == 0
        assert h in store.list_hashes(tier="operational")

    def test_rotate_skips_locked(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"locked_receipt"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        store.lock(h)
        # Force stored_at old
        store._conn.execute(
            "UPDATE receipts SET stored_at=? WHERE receipt_hash=?",
            (time.time() - 50 * 3600, h),
        )
        store._conn.commit()
        rotated = store.rotate_operational(hours=48)
        assert rotated == 0  # locked receipt must not be rotated
        info = store.get_receipt_info(h)
        assert info is not None
        assert info["tier"] == "crash_protected"


class TestSqliteReceiptStoreWalCheckpoint:
    """GREEN: rotate_operational() must checkpoint+truncate the -wal sidecar
    so it does not retain pre-rotation page versions after process exit."""

    def test_rotate_truncates_wal_sidecar(self, tmp_path) -> None:
        db_path = str(tmp_path / "receipts.db")
        wal_path = db_path + "-wal"
        store = SqliteReceiptStore(db_path=db_path)

        marker = b"WAL_CHECKPOINT_MARKER_" + os.urandom(8).hex().encode()
        h = hashlib.sha3_256(marker).hexdigest()
        store.put(h, marker)
        store._conn.execute(
            "UPDATE receipts SET stored_at=? WHERE receipt_hash=?",
            (time.time() - 50 * 3600, h),
        )
        store._conn.commit()

        # Sanity check: before any checkpoint, the WAL sidecar actually holds
        # the marker (proves the test exercises the real WAL-persistence risk).
        assert os.path.exists(wal_path)
        with open(wal_path, "rb") as f:
            assert marker in f.read()

        rotated = store.rotate_operational(hours=48)
        assert rotated == 1

        # After rotation, the sidecar must be checkpointed away (TRUNCATE
        # leaves it at zero length) — no stale pre-rotation content remains.
        assert os.path.getsize(wal_path) == 0

        # Rotation promotes tier, it does not delete the receipt itself.
        assert store.get(h) == marker


class TestSqliteFromEnv:
    def test_dev_mode_returns_memory_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEVUM_DEV", "1")
        monkeypatch.delenv("AEVUM_RECEIPT_DB", raising=False)
        store = SqliteReceiptStore.from_env()
        assert store._db_path == ":memory:"

    def test_missing_db_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEVUM_DEV", raising=False)
        monkeypatch.delenv("AEVUM_RECEIPT_DB", raising=False)
        with pytest.raises(RuntimeError, match="AEVUM_RECEIPT_DB"):
            SqliteReceiptStore.from_env()

    def test_db_path_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
        import os
        db = os.path.join(str(tmp_path), "test.db")
        monkeypatch.delenv("AEVUM_DEV", raising=False)
        monkeypatch.setenv("AEVUM_RECEIPT_DB", db)
        store = SqliteReceiptStore.from_env()
        assert store._db_path == db


# ── NullReceiptStore ──────────────────────────────────────────────────────────

class TestNullReceiptStore:
    def test_satisfies_protocol(self) -> None:
        null = NullReceiptStore()
        assert isinstance(null, ReceiptStore)

    def test_put_and_get_discards(self) -> None:
        null = NullReceiptStore()
        null.put("h", b"blob")
        assert null.get("h") is None

    def test_lock_is_silent_noop(self) -> None:
        null = NullReceiptStore()
        null.lock("any_hash")  # must not raise

    def test_list_hashes_empty(self) -> None:
        assert NullReceiptStore().list_hashes() == []

    def test_ambient_discards(self) -> None:
        null = NullReceiptStore()
        null.put_ambient("s", b"blob", "sess", "PERIODIC")
        assert null.get_ambient("s") is None


# ── Escalation logic ─────────────────────────────────────────────────────────

class TestEscalation:
    def test_escalates_on_deny_barrier(self) -> None:
        assert should_escalate("tool_call", None, None, {"Crisis": "DENY"}) is True

    def test_escalates_on_human_reject(self) -> None:
        assert should_escalate("tool_call", None, "REJECT", {}) is True

    def test_escalates_on_minimum_risk(self) -> None:
        assert should_escalate("tool_call", "MINIMUM_RISK", None, {}) is True

    def test_escalates_on_failure(self) -> None:
        assert should_escalate("tool_call", "FAILURE", None, {}) is True

    def test_escalates_on_odd_exit(self) -> None:
        assert should_escalate("tool_call", "ODD_EXIT", None, {}) is True

    def test_no_escalation_for_allow(self) -> None:
        assert should_escalate("tool_call", None, None, {"Crisis": "ALLOW"}) is False

    def test_no_escalation_for_normal(self) -> None:
        assert should_escalate("tool_call", None, None, {}) is False

    def test_escalate_if_triggered_locks(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"escalate_me"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        escalated = escalate_if_triggered(
            store=store,
            receipt_hash=h,
            event_action="tool_call",
            handoff_type="MINIMUM_RISK",
            human_override_action=None,
            barrier_evaluations={},
        )
        assert escalated is True
        info = store.get_receipt_info(h)
        assert info is not None
        assert info["locked"] is True

    def test_escalate_if_triggered_no_lock_on_normal(self) -> None:
        store = SqliteReceiptStore(db_path=":memory:")
        blob = b"normal_event"
        h = hashlib.sha3_256(blob).hexdigest()
        store.put(h, blob)
        escalated = escalate_if_triggered(
            store=store,
            receipt_hash=h,
            event_action="query",
            handoff_type=None,
            human_override_action=None,
            barrier_evaluations={},
        )
        assert escalated is False
        info = store.get_receipt_info(h)
        assert info is not None
        assert info["locked"] is False
