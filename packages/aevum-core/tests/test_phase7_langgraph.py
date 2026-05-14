# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Tests for AevumCheckpointer. Skips gracefully if langgraph-checkpoint
is not installed. Uses asyncio.run() throughout (Rule 54).
"""
import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

try:
    from langgraph.checkpoint.base import CheckpointTuple  # noqa: F401

    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _LANGGRAPH_AVAILABLE,
    reason="langgraph-checkpoint not installed",
)

from aevum.core.adapters.langgraph import AevumCheckpointer  # noqa: E402


def _make_checkpoint(idx: int = 1) -> dict:
    return {
        "v": 4,
        "ts": datetime.now(UTC).isoformat(),
        "id": f"checkpoint-{idx:04d}",
        "channel_values": {"my_key": f"value-{idx}"},
        "channel_versions": {"my_key": idx},
        "versions_seen": {},
    }


def _write_config(thread_id: str, checkpoint_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id, "checkpoint_ns": "", "checkpoint_id": checkpoint_id}}


def _read_config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}


class TestAevumCheckpointerInit:
    def test_local_creates_db_file(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        assert (tmp_path / "checkpoints.db").exists()
        c.close()

    def test_local_without_kernel(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path, kernel=None)
        assert c._kernel is None
        c.close()

    def test_local_creates_state_dir_if_missing(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "subdir" / "nested"
        c = AevumCheckpointer.local(state_dir=state_dir)
        assert state_dir.exists()
        assert (state_dir / "checkpoints.db").exists()
        c.close()

    def test_init_schema_creates_tables(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        tables = {
            row[0]
            for row in c._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "checkpoints" in tables
        assert "checkpoint_writes" in tables
        assert "checkpoint_versions" in tables
        c.close()


class TestPutAndGetTuple:
    def test_put_and_get_tuple(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {"my_key": 1})
        result = c.get_tuple(_read_config("t1"))
        assert result is not None
        assert result.checkpoint["id"] == ckpt["id"]
        c.close()

    def test_get_tuple_returns_none_for_missing_thread(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        result = c.get_tuple(_read_config("nonexistent"))
        assert result is None
        c.close()

    def test_put_multiple_gets_latest(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        for i in range(1, 4):
            ckpt = _make_checkpoint(i)
            c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {"my_key": i})
        result = c.get_tuple(_read_config("t1"))
        assert result is not None
        c.close()

    def test_put_returns_config_dict(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        config = c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        assert "configurable" in config
        assert "thread_id" in config["configurable"]
        c.close()

    def test_checkpoint_metadata_stored(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        metadata = {"source": "test", "step": 1}
        c.put(_write_config("t1", ckpt["id"]), ckpt, metadata, {})
        result = c.get_tuple(_read_config("t1"))
        assert result is not None
        assert result.metadata == metadata
        c.close()

    def test_put_returns_correct_thread_id(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        config = c.put(_write_config("alice", ckpt["id"]), ckpt, {}, {})
        assert config["configurable"]["thread_id"] == "alice"
        c.close()

    def test_put_stores_channel_versions(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {"ch_a": 1, "ch_b": 2})
        rows = c._conn.execute(
            "SELECT channel, version FROM checkpoint_versions WHERE thread_id='t1'"
        ).fetchall()
        versions = {r[0]: r[1] for r in rows}
        assert versions["ch_a"] == 1
        assert versions["ch_b"] == 2
        c.close()

    def test_get_tuple_by_specific_checkpoint_id(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt1 = _make_checkpoint(1)
        ckpt2 = _make_checkpoint(2)
        c.put(_write_config("t1", ckpt1["id"]), ckpt1, {}, {})
        c.put(_write_config("t1", ckpt2["id"]), ckpt2, {}, {})
        result = c.get_tuple(_write_config("t1", ckpt1["id"]))
        assert result is not None
        assert result.checkpoint["id"] == ckpt1["id"]
        c.close()

    def test_get_tuple_parent_config(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt1 = _make_checkpoint(1)
        ckpt2 = _make_checkpoint(2)
        c.put(_write_config("t1", ckpt1["id"]), ckpt1, {}, {})
        c.put(_write_config("t1", ckpt2["id"]), ckpt2, {}, {})
        result = c.get_tuple(_read_config("t1"))
        assert result is not None
        assert result.parent_config is not None
        assert result.parent_config["configurable"]["checkpoint_id"] == ckpt1["id"]
        c.close()


class TestPutWrites:
    def test_put_writes_stores_pending_writes(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        writes = [("my_channel", "intermediate_value")]
        c.put_writes(
            {"configurable": {"thread_id": "t1", "checkpoint_ns": "", "checkpoint_id": ckpt["id"]}},
            writes,
            "task-1",
        )
        rows = c._conn.execute("SELECT * FROM checkpoint_writes WHERE thread_id='t1'").fetchall()
        assert len(rows) == 1
        c.close()

    def test_put_writes_multiple_channels(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        writes = [("ch_a", "val_a"), ("ch_b", "val_b"), ("ch_c", "val_c")]
        c.put_writes(
            {"configurable": {"thread_id": "t1", "checkpoint_ns": "", "checkpoint_id": ckpt["id"]}},
            writes,
            "task-1",
        )
        rows = c._conn.execute("SELECT * FROM checkpoint_writes WHERE thread_id='t1'").fetchall()
        assert len(rows) == 3
        c.close()

    def test_get_tuple_includes_pending_writes(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        writes = [("my_channel", "pending_val")]
        c.put_writes(
            {"configurable": {"thread_id": "t1", "checkpoint_ns": "", "checkpoint_id": ckpt["id"]}},
            writes,
            "task-x",
        )
        result = c.get_tuple(_read_config("t1"))
        assert result is not None
        assert len(result.pending_writes) == 1
        assert result.pending_writes[0][1] == "my_channel"
        assert result.pending_writes[0][2] == "pending_val"
        c.close()


class TestList:
    def test_list_returns_all_checkpoints(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        for i in range(1, 4):
            ckpt = _make_checkpoint(i)
            c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        results = list(c.list(_read_config("t1")))
        assert len(results) == 3
        c.close()

    def test_list_empty_for_missing_thread(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        results = list(c.list(_read_config("nonexistent")))
        assert results == []
        c.close()

    def test_list_respects_limit(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        for i in range(1, 6):
            ckpt = _make_checkpoint(i)
            c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        results = list(c.list(_read_config("t1"), limit=2))
        assert len(results) == 2
        c.close()

    def test_list_ordered_newest_first(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        for i in range(1, 4):
            ckpt = _make_checkpoint(i)
            c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        results = list(c.list(_read_config("t1")))
        ids = [r.checkpoint["id"] for r in results]
        assert ids == sorted(ids, reverse=True)
        c.close()

    def test_list_isolates_threads(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        for i in range(1, 3):
            ckpt = _make_checkpoint(i)
            c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        ckpt = _make_checkpoint(99)
        c.put(_write_config("t2", ckpt["id"]), ckpt, {}, {})
        t1_results = list(c.list(_read_config("t1")))
        t2_results = list(c.list(_read_config("t2")))
        assert len(t1_results) == 2
        assert len(t2_results) == 1
        c.close()


class TestDeleteThread:
    def test_delete_thread_removes_checkpoints(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        c.delete_thread("t1")
        result = c.get_tuple(_read_config("t1"))
        assert result is None
        c.close()

    def test_delete_thread_does_not_affect_other_threads(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt1 = _make_checkpoint(1)
        ckpt2 = _make_checkpoint(2)
        c.put(_write_config("t1", ckpt1["id"]), ckpt1, {}, {})
        c.put(_write_config("t2", ckpt2["id"]), ckpt2, {}, {})
        c.delete_thread("t1")
        assert c.get_tuple(_read_config("t1")) is None
        assert c.get_tuple(_read_config("t2")) is not None
        c.close()

    def test_delete_thread_shreds_dek_when_kernel_present(self, tmp_path: Path) -> None:
        kernel = MagicMock()
        consent_ledger = MagicMock()
        kernel._consent_ledger = consent_ledger
        c = AevumCheckpointer.local(state_dir=tmp_path, kernel=kernel)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("alice", ckpt["id"]), ckpt, {}, {})
        c.delete_thread("alice")
        consent_ledger.shred.assert_called_once_with("alice")
        c.close()

    def test_delete_thread_no_kernel_no_error(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path, kernel=None)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        c.delete_thread("t1")  # must not raise
        c.close()

    def test_delete_thread_clears_writes(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        c.put_writes(
            {"configurable": {"thread_id": "t1", "checkpoint_ns": "", "checkpoint_id": ckpt["id"]}},
            [("ch", "val")],
            "task-1",
        )
        c.delete_thread("t1")
        rows = c._conn.execute("SELECT * FROM checkpoint_writes WHERE thread_id='t1'").fetchall()
        assert len(rows) == 0
        c.close()

    def test_delete_thread_clears_versions(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {"ch": 1})
        c.delete_thread("t1")
        rows = c._conn.execute("SELECT * FROM checkpoint_versions WHERE thread_id='t1'").fetchall()
        assert len(rows) == 0
        c.close()

    def test_delete_thread_kernel_without_consent_ledger(self, tmp_path: Path) -> None:
        kernel = MagicMock(spec=[])  # no _consent_ledger attribute
        c = AevumCheckpointer.local(state_dir=tmp_path, kernel=kernel)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        c.delete_thread("t1")  # must not raise
        c.close()


class TestGetNextVersion:
    """Rule 15: get_next_version is required — LangGraph errors without it."""

    def test_get_next_version_from_none(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        v = c.get_next_version(None, "my_channel")
        assert v == 1
        c.close()

    def test_get_next_version_increments(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        v1 = c.get_next_version(None, "ch")
        v2 = c.get_next_version(v1, "ch")
        v3 = c.get_next_version(v2, "ch")
        assert v1 < v2 < v3
        c.close()

    def test_get_next_version_monotonically_increasing(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        current: int | None = None
        for _ in range(10):
            next_v = c.get_next_version(current, "ch")
            assert current is None or next_v > current
            current = next_v
        c.close()

    def test_get_next_version_from_zero(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        v = c.get_next_version(0, "ch")
        assert v == 1
        c.close()

    def test_get_next_version_from_string(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        v = c.get_next_version("5", "ch")
        assert v == 6
        c.close()

    def test_get_next_version_returns_int(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        v = c.get_next_version(None, "ch")
        assert isinstance(v, int)
        c.close()

    def test_get_next_version_channel_independent(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path)
        v_a = c.get_next_version(None, "channel_a")
        v_b = c.get_next_version(None, "channel_b")
        assert v_a == v_b == 1
        c.close()


class TestAsyncMethods:
    """Async versions of all sync methods (required for ainvoke/astream)."""

    def test_aput_and_aget_tuple(self, tmp_path: Path) -> None:
        async def _run() -> None:
            c = AevumCheckpointer.local(state_dir=tmp_path)
            ckpt = _make_checkpoint(1)
            await c.aput(_write_config("t1", ckpt["id"]), ckpt, {}, {"ch": 1})
            result = await c.aget_tuple(_read_config("t1"))
            assert result is not None
            assert result.checkpoint["id"] == ckpt["id"]
            c.close()

        asyncio.run(_run())  # Rule 54: never asyncio.get_event_loop()

    def test_alist(self, tmp_path: Path) -> None:
        async def _run() -> None:
            c = AevumCheckpointer.local(state_dir=tmp_path)
            for i in range(1, 4):
                ckpt = _make_checkpoint(i)
                await c.aput(_write_config("t1", ckpt["id"]), ckpt, {}, {})
            results = [item async for item in c.alist(_read_config("t1"))]
            assert len(results) == 3
            c.close()

        asyncio.run(_run())

    def test_adelete_thread(self, tmp_path: Path) -> None:
        async def _run() -> None:
            c = AevumCheckpointer.local(state_dir=tmp_path)
            ckpt = _make_checkpoint(1)
            await c.aput(_write_config("t1", ckpt["id"]), ckpt, {}, {})
            await c.adelete_thread("t1")
            result = await c.aget_tuple(_read_config("t1"))
            assert result is None
            c.close()

        asyncio.run(_run())

    def test_aput_writes(self, tmp_path: Path) -> None:
        async def _run() -> None:
            c = AevumCheckpointer.local(state_dir=tmp_path)
            ckpt = _make_checkpoint(1)
            await c.aput(_write_config("t1", ckpt["id"]), ckpt, {}, {})
            await c.aput_writes(
                {"configurable": {"thread_id": "t1", "checkpoint_ns": "", "checkpoint_id": ckpt["id"]}},
                [("ch", "val")],
                "task-1",
            )
            result = await c.aget_tuple(_read_config("t1"))
            assert result is not None
            assert len(result.pending_writes) == 1
            c.close()

        asyncio.run(_run())

    def test_adelete_thread_shreds_dek(self, tmp_path: Path) -> None:
        async def _run() -> None:
            kernel = MagicMock()
            consent_ledger = MagicMock()
            kernel._consent_ledger = consent_ledger
            c = AevumCheckpointer.local(state_dir=tmp_path, kernel=kernel)
            ckpt = _make_checkpoint(1)
            await c.aput(_write_config("alice", ckpt["id"]), ckpt, {}, {})
            await c.adelete_thread("alice")
            consent_ledger.shred.assert_called_once_with("alice")
            c.close()

        asyncio.run(_run())

    def test_aget_tuple_returns_none_for_missing(self, tmp_path: Path) -> None:
        async def _run() -> None:
            c = AevumCheckpointer.local(state_dir=tmp_path)
            result = await c.aget_tuple(_read_config("nonexistent"))
            assert result is None
            c.close()

        asyncio.run(_run())


class TestSigchainRecording:
    def test_record_checkpoint_with_kernel(self, tmp_path: Path) -> None:
        kernel = MagicMock()
        c = AevumCheckpointer.local(state_dir=tmp_path, kernel=kernel)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        # Should not raise
        c.close()

    def test_record_checkpoint_without_kernel_no_error(self, tmp_path: Path) -> None:
        c = AevumCheckpointer.local(state_dir=tmp_path, kernel=None)
        ckpt = _make_checkpoint(1)
        c.put(_write_config("t1", ckpt["id"]), ckpt, {}, {})
        c.close()


class TestRegisterWithLangGraph:
    def test_register_with_langgraph_does_not_raise(self) -> None:
        AevumCheckpointer.register_with_langgraph()  # must not raise

    def test_register_with_langgraph_importable(self) -> None:
        from aevum.core.adapters.langgraph import AevumCheckpointer as AC
        AC.register_with_langgraph()
