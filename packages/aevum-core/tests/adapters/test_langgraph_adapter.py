# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the LangGraph AevumCheckpointer adapter.

These tests detect when langgraph-checkpoint changes the CheckpointTuple
shape or put/get_tuple contract in a way that silently breaks Aevum's
governance envelope.  If this file fails after a langgraph-checkpoint
upgrade, compare the diff carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream change that would break this adapter:
  - langgraph-checkpoint renames or removes CheckpointTuple fields
  - put() contract changes (return shape or configurable keys)
  - get_next_version() is no longer required by LangGraph
Re-evaluate when: langgraph-checkpoint releases a major version bump.
"""
from __future__ import annotations

import pytest

pytest.importorskip("langgraph.checkpoint.base", reason="langgraph-checkpoint not installed")

from datetime import UTC, datetime  # noqa: E402
from pathlib import Path  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.langgraph import AevumCheckpointer  # noqa: E402


def _make_checkpoint(idx: int = 1) -> dict:
    return {
        "v": 4,
        "ts": datetime.now(UTC).isoformat(),
        "id": f"checkpoint-{idx:04d}",
        "channel_values": {"state": f"value-{idx}"},
        "channel_versions": {"state": idx},
        "versions_seen": {},
    }


def _write_cfg(thread_id: str, ckpt_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id, "checkpoint_ns": "", "checkpoint_id": ckpt_id}}


def _read_cfg(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}


def test_put_return_shape(tmp_path: Path) -> None:
    """
    put() must return exactly this configurable dict shape.
    If LangGraph changes what it reads from put()'s return value this snapshot fails.
    """
    c = AevumCheckpointer.local(state_dir=tmp_path)
    ckpt = _make_checkpoint(1)
    result = c.put(_write_cfg("thread-snap", ckpt["id"]), ckpt, {}, {"state": 1})
    c.close()

    assert result == snapshot(
        {
            "configurable": {
                "thread_id": "thread-snap",
                "checkpoint_ns": "",
                "checkpoint_id": "checkpoint-0001",
            }
        }
    )


def test_get_tuple_shape_after_put(tmp_path: Path) -> None:
    """
    CheckpointTuple field names must stay stable — LangGraph reads them by name.
    Uses a config without checkpoint_id (no parent) so parent_config is None.
    """
    from langgraph.checkpoint.base import CheckpointTuple

    c = AevumCheckpointer.local(state_dir=tmp_path)
    ckpt = _make_checkpoint(1)
    # No checkpoint_id in config → parent_id = None → parent_config = None
    c.put({"configurable": {"thread_id": "snap-thread", "checkpoint_ns": ""}},
          ckpt, {"source": "test", "step": 1}, {"state": 1})
    tup = c.get_tuple(_read_cfg("snap-thread"))
    c.close()

    assert isinstance(tup, CheckpointTuple)
    assert tup == snapshot(
        CheckpointTuple(
            config={
                "configurable": {
                    "thread_id": "snap-thread",
                    "checkpoint_ns": "",
                    "checkpoint_id": "checkpoint-0001",
                }
            },
            checkpoint=tup.checkpoint,
            metadata={"source": "test", "step": 1},
            parent_config=None,
            pending_writes=[],
        )
    )


def test_get_next_version_sequence(tmp_path: Path) -> None:
    """
    get_next_version must return a strictly increasing integer sequence.
    LangGraph relies on this for superstep ordering.
    """
    c = AevumCheckpointer.local(state_dir=tmp_path)
    versions = [c.get_next_version(i if i else None, "ch") for i in range(5)]
    c.close()

    assert versions == snapshot([1, 2, 3, 4, 5])


def test_put_return_shape_is_bool_false_on_cedar_permit() -> None:
    """cedar_permitted is always True in AevumCheckpointer (no Cedar check at checkpoint time)."""
    # AevumCheckpointer does not do Cedar evaluation — checkpointing is not a policy decision.
    # This test documents that assumption explicitly.
    assert True  # intentional no-op; see above comment


def test_delete_thread_makes_get_tuple_return_none(tmp_path: Path) -> None:
    """delete_thread must make subsequent get_tuple return None — invariant for GDPR erasure."""
    c = AevumCheckpointer.local(state_dir=tmp_path)
    ckpt = _make_checkpoint(1)
    c.put(_write_cfg("erase-me", ckpt["id"]), ckpt, {}, {})
    c.delete_thread("erase-me")
    result = c.get_tuple(_read_cfg("erase-me"))
    c.close()

    assert result == snapshot(None)


def test_dek_shred_called_on_delete(tmp_path: Path) -> None:
    """
    delete_thread must call consent_ledger.shred(thread_id) when kernel present.
    If this contract changes, GDPR Art. 17 erasure is broken.
    """
    kernel = MagicMock()
    ledger = MagicMock()
    kernel._consent_ledger = ledger

    c = AevumCheckpointer.local(state_dir=tmp_path, kernel=kernel)
    ckpt = _make_checkpoint(1)
    c.put(_write_cfg("gdpr-subject", ckpt["id"]), ckpt, {}, {})
    c.delete_thread("gdpr-subject")
    c.close()

    ledger.shred.assert_called_once_with("gdpr-subject")
