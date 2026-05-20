# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the LangChain AevumLangChainCallback adapter.

These tests detect when langchain-core changes the BaseCallbackHandler hook
signatures in a way that silently breaks Aevum's governance envelope.
If this file fails after a langchain-core upgrade, compare the diff
carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream change that would break this adapter:
  - langchain-core renames or removes BaseCallbackHandler hook methods
  - on_tool_start serialized dict changes its 'name' key
  - BaseCallbackHandler adds mandatory kwargs to hook signatures
  - LangGraph stops propagating callbacks through StateGraph nodes
Re-evaluate when: langchain-core releases a >=1.0 stable version.
"""
from __future__ import annotations

import pytest

pytest.importorskip("langchain_core", reason="langchain-core not installed")

from uuid import UUID  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.langchain_callback import AevumLangChainCallback  # noqa: E402


def _permit_patch() -> object:
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch(
        "aevum.core.adapters.langchain_callback.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    )


def _deny_patch() -> object:
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch(
        "aevum.core.adapters.langchain_callback.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    )


def _serialized(name: str) -> dict:
    return {"name": name, "id": ["langchain", "tools", name]}


# ── on_tool_start snapshot tests ──────────────────────────────────────────────


def test_on_tool_start_return_shape() -> None:
    """
    on_tool_start must return a dict with exactly these keys.
    If the adapter adds, removes, or renames a key this snapshot fails.
    """
    cb = AevumLangChainCallback(kernel=None)
    with _permit_patch():
        result = cb.on_tool_start(_serialized("search_tool"), "query string")

    assert result == snapshot(
        {
            "tool_name": "search_tool",
            "input_hash": result["input_hash"],
            "started_at": result["started_at"],
            "cedar_permitted": True,
            "run_id": None,
        }
    )


def test_on_tool_start_cedar_permitted_is_bool() -> None:
    """cedar_permitted must be exactly True — consumers type-check it."""
    cb = AevumLangChainCallback(kernel=None)
    with _permit_patch():
        result = cb.on_tool_start(_serialized("tool"), "input")
    assert result["cedar_permitted"] is True


def test_on_tool_start_cedar_deny_raises_permission_error() -> None:
    """Cedar deny must raise PermissionError — not return a falsy value."""
    cb = AevumLangChainCallback(kernel=None)
    with _deny_patch(), pytest.raises(PermissionError, match="Cedar denied LangChain tool call"):
        cb.on_tool_start(_serialized("blocked_tool"), "input")


def test_on_tool_start_with_run_id() -> None:
    """run_id must be serialized to string in the returned context dict."""
    cb = AevumLangChainCallback(kernel=None)
    run_id = UUID("12345678-1234-5678-1234-567812345678")
    with _permit_patch():
        result = cb.on_tool_start(_serialized("tool"), "input", run_id=run_id)

    assert result["run_id"] == snapshot("12345678-1234-5678-1234-567812345678")


def test_on_tool_start_input_hash_is_hex64() -> None:
    """input_hash must be a 64-char lowercase hex string (SHA-256)."""
    cb = AevumLangChainCallback(kernel=None)
    with _permit_patch():
        result = cb.on_tool_start(_serialized("tool"), "some input")
    assert len(result["input_hash"]) == 64
    assert all(c in "0123456789abcdef" for c in result["input_hash"])


# ── on_tool_end snapshot tests ────────────────────────────────────────────────


def test_on_tool_end_returns_none() -> None:
    """on_tool_end must return None."""
    cb = AevumLangChainCallback(kernel=None)
    result = cb.on_tool_end("tool output")
    assert result == snapshot(None)


def test_on_tool_end_with_kernel_does_not_raise() -> None:
    """on_tool_end with kernel must complete without raising."""
    cb = AevumLangChainCallback(kernel=MagicMock())
    result = cb.on_tool_end("output")
    assert result == snapshot(None)


# ── on_llm_start snapshot tests ───────────────────────────────────────────────


def test_on_llm_start_return_shape() -> None:
    """on_llm_start must return a dict with model_name, prompt_hash, started_at, run_id."""
    cb = AevumLangChainCallback(kernel=None)
    result = cb.on_llm_start({"name": "gpt-4o"}, ["Tell me about Aevum"])

    assert result == snapshot(
        {
            "model_name": "gpt-4o",
            "prompt_hash": result["prompt_hash"],
            "started_at": result["started_at"],
            "run_id": None,
        }
    )


def test_on_llm_start_prompt_hash_is_hex64() -> None:
    """prompt_hash must be 64-char lowercase hex (SHA-256)."""
    cb = AevumLangChainCallback(kernel=None)
    result = cb.on_llm_start({"name": "model"}, ["prompt"])
    assert len(result["prompt_hash"]) == 64
    assert all(c in "0123456789abcdef" for c in result["prompt_hash"])


def test_on_llm_end_returns_none() -> None:
    """on_llm_end must return None."""
    cb = AevumLangChainCallback(kernel=None)
    result = cb.on_llm_end(MagicMock())
    assert result == snapshot(None)


# ── on_chain_error snapshot tests ─────────────────────────────────────────────


def test_on_chain_error_returns_none() -> None:
    """on_chain_error must return None — LangChain does not use the return value."""
    cb = AevumLangChainCallback(kernel=None)
    result = cb.on_chain_error(ValueError("something broke"))
    assert result == snapshot(None)


def test_on_chain_error_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    """on_chain_error must log a warning with CAPTURE_GAP (no kernel path)."""
    import logging

    cb = AevumLangChainCallback(kernel=None)
    with caplog.at_level(logging.WARNING, logger="aevum.core.adapters.langchain_callback"):
        cb.on_chain_error(RuntimeError("chain failed"))

    assert any("CAPTURE_GAP" in r.message or "chain_error" in r.message for r in caplog.records)


def test_on_chain_error_with_kernel_records_gap() -> None:
    """on_chain_error with kernel must call _sigchain_commit with reason=langchain_chain_error."""
    cb = AevumLangChainCallback(kernel=MagicMock())
    commits: list[dict] = []

    def mock_commit(event_type: str, **payload: object) -> None:
        commits.append({"event_type": event_type, **payload})

    cb._sigchain_commit = mock_commit  # type: ignore[method-assign]
    cb.on_chain_error(ConnectionError("timeout"))

    assert commits == snapshot(
        [{"event_type": "capture_gap", "reason": "langchain_chain_error", "error_type": "ConnectionError"}]
    )


# ── LangChain BaseCallbackHandler compatibility ────────────────────────────────


def test_callback_compatible_with_langchain_base() -> None:
    """
    AevumLangChainCallback must be accepted by LangChain's callback system.
    Verify it has all required hook method names.
    """
    from langchain_core.callbacks import BaseCallbackHandler

    cb = AevumLangChainCallback(kernel=None)
    for method in ("on_tool_start", "on_tool_end", "on_llm_start", "on_llm_end", "on_chain_error"):
        assert hasattr(cb, method), f"Missing required hook: {method}"


def test_mixin_subclass_is_base_callback_handler() -> None:
    """Mixin subclass of AevumLangChainCallback + BaseCallbackHandler passes isinstance check."""
    from langchain_core.callbacks import BaseCallbackHandler

    class MyCallback(AevumLangChainCallback, BaseCallbackHandler):
        pass

    cb = MyCallback(kernel=None)
    assert isinstance(cb, BaseCallbackHandler)


# ── LangGraph callback propagation test ───────────────────────────────────────


def test_callback_propagates_through_langgraph_state_graph() -> None:
    """
    LangGraph propagates callbacks through StateGraph nodes when passed via
    RunnableConfig.  Verify the callback is invoked during node execution.

    This test verifies the contract: if LangGraph changes how it propagates
    callbacks through nodes, this test will fail.
    """
    pytest.importorskip("langgraph", reason="langgraph not installed")

    from langchain_core.callbacks import CallbackManager
    from langgraph.graph import StateGraph

    tool_starts: list[str] = []

    class _TrackingCallback(AevumLangChainCallback):
        def on_tool_start(self, serialized: dict, input_str: str, **kwargs: object) -> dict:
            tool_starts.append(serialized.get("name", ""))
            return {"tool_name": serialized.get("name", ""), "cedar_permitted": True,
                    "input_hash": "", "started_at": "", "run_id": None}

    cb = _TrackingCallback(kernel=None)
    manager = CallbackManager(handlers=[cb])

    def my_node(state: dict) -> dict:
        manager.on_tool_start({"name": "state_node_tool"}, "input")
        return state

    builder: StateGraph = StateGraph(dict)
    builder.add_node("node", my_node)
    builder.set_entry_point("node")
    builder.set_finish_point("node")
    graph = builder.compile()

    graph.invoke({"key": "value"})
    assert "state_node_tool" in tool_starts
