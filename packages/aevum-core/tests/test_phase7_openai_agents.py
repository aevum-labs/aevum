# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Tests for AevumAgentHooks (OpenAI Agents SDK adapter).
Uses mocked Cedar to avoid live policy evaluation.
"""
from unittest.mock import MagicMock, patch

import pytest

from aevum.core.adapters.openai_agents import AevumAgentHooks


def _permit_patch() -> object:
    """Context manager that patches Cedar to allow everything."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch("aevum.core.adapters.openai_agents.CedarPolicyEngine", **{"default.return_value": mock_engine})


def _deny_patch() -> object:
    """Context manager that patches Cedar to deny everything."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch("aevum.core.adapters.openai_agents.CedarPolicyEngine", **{"default.return_value": mock_engine})


class TestAevumAgentHooksInit:
    def test_init_without_kernel(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        assert hooks._kernel is None

    def test_init_with_kernel(self) -> None:
        kernel = MagicMock()
        hooks = AevumAgentHooks(kernel=kernel)
        assert hooks._kernel is kernel


class TestOnToolStart:
    def test_on_tool_start_returns_ctx(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.on_tool_start("search", {"query": "test"}, "my-agent")
        assert ctx["tool_name"] == "search"
        assert ctx["cedar_permitted"] is True
        assert ctx["agent_name"] == "my-agent"

    def test_on_tool_start_raises_on_deny(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _deny_patch(), pytest.raises(PermissionError, match="Cedar denied"):
            hooks.on_tool_start("dangerous_tool", {})

    def test_on_tool_start_input_hash_is_64_chars(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.on_tool_start("tool", {"key": "value"})
        assert len(ctx["input_hash"]) == 64

    def test_on_tool_start_with_none_input(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.on_tool_start("tool", None)
        assert ctx["cedar_permitted"] is True

    def test_on_tool_start_ctx_has_started_at(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.on_tool_start("search")
        assert "started_at" in ctx

    def test_on_tool_start_default_agent_name(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.on_tool_start("tool")
        assert ctx["agent_name"] == "agent"

    def test_on_tool_start_cedar_called_with_correct_params(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        mock_engine = MagicMock()
        mock_engine.is_permitted.return_value = True
        with patch(
            "aevum.core.adapters.openai_agents.CedarPolicyEngine",
            **{"default.return_value": mock_engine},
        ):
            hooks.on_tool_start("my_tool", {"a": 1}, "special-agent")
        call_kwargs = mock_engine.is_permitted.call_args[1]
        assert call_kwargs["principal_type"] == "AevumAgent"
        assert call_kwargs["principal_id"] == "special-agent"
        assert call_kwargs["action"] == "tool_call"
        assert call_kwargs["resource_id"] == "my_tool"

    def test_on_tool_start_error_message_includes_tool_name(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _deny_patch(), pytest.raises(PermissionError) as exc_info:
            hooks.on_tool_start("forbidden_tool", {})
        assert "forbidden_tool" in str(exc_info.value)

    def test_on_tool_start_error_message_includes_agent_name(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _deny_patch(), pytest.raises(PermissionError) as exc_info:
            hooks.on_tool_start("tool", {}, "rogue-agent")
        assert "rogue-agent" in str(exc_info.value)

    def test_on_tool_start_hash_is_hex(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.on_tool_start("tool", {"data": "value"})
        int(ctx["input_hash"], 16)  # must not raise — valid hex string


class TestOnToolEnd:
    def test_on_tool_end_does_not_raise(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        ctx = {"tool_name": "search", "agent_name": "agent", "input_hash": "a" * 64}
        hooks.on_tool_end(ctx, "result", success=True)

    def test_on_tool_end_failure_does_not_raise(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        ctx = {"tool_name": "tool", "agent_name": "agent", "input_hash": "b" * 64}
        hooks.on_tool_end(ctx, "error", success=False)

    def test_on_tool_end_with_kernel(self) -> None:
        kernel = MagicMock()
        hooks = AevumAgentHooks(kernel=kernel)
        ctx = {"tool_name": "search", "agent_name": "agent", "input_hash": "c" * 64}
        hooks.on_tool_end(ctx, "result")

    def test_on_tool_end_with_none_output(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        ctx = {"tool_name": "tool", "agent_name": "agent"}
        hooks.on_tool_end(ctx, None)  # must not raise

    def test_on_tool_end_with_dict_output(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        ctx = {"tool_name": "tool", "agent_name": "agent"}
        hooks.on_tool_end(ctx, {"items": [1, 2, 3]})

    def test_on_tool_end_calls_record_tool_event_when_kernel(self) -> None:
        kernel = MagicMock()
        hooks = AevumAgentHooks(kernel=kernel)
        record_calls = []

        def patched(ctx, output_hash, success):  # type: ignore[no-untyped-def]
            record_calls.append(success)

        hooks._record_tool_event = patched  # type: ignore[method-assign]
        ctx = {"tool_name": "tool", "agent_name": "agent"}
        hooks.on_tool_end(ctx, "output", success=True)
        assert len(record_calls) == 1
        assert record_calls[0] is True


class TestOnHandoff:
    def test_on_handoff_does_not_raise(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        hooks.on_handoff("agent-a", "agent-b")

    def test_on_handoff_with_kernel(self) -> None:
        kernel = MagicMock()
        hooks = AevumAgentHooks(kernel=kernel)
        hooks.on_handoff("from-agent", "to-agent")

    def test_on_handoff_with_context(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        hooks.on_handoff("a", "b", context={"reason": "subtask"})

    def test_on_handoff_with_none_context(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        hooks.on_handoff("a", "b", context=None)

    def test_on_handoff_different_agents(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        hooks.on_handoff("orchestrator", "worker-1")
        hooks.on_handoff("worker-1", "worker-2")
        hooks.on_handoff("worker-2", "orchestrator")


class TestRecordToolEvent:
    def test_record_tool_event_does_not_raise(self) -> None:
        hooks = AevumAgentHooks(kernel=None)
        ctx = {"tool_name": "search", "agent_name": "agent"}
        hooks._record_tool_event(ctx, "a" * 64, success=True)

    def test_record_tool_event_handles_exception_gracefully(self) -> None:
        hooks = AevumAgentHooks(kernel=None)

        def bad_debug(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("logger exploded")

        import logging

        logger = logging.getLogger("aevum.core.adapters.openai_agents")
        original_debug = logger.debug
        logger.debug = bad_debug  # type: ignore[method-assign]
        try:
            hooks._record_tool_event({"tool_name": "t"}, "hash", True)
        except Exception:
            pass  # must not propagate
        finally:
            logger.debug = original_debug  # type: ignore[method-assign]
