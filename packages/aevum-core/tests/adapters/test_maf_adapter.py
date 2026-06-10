# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the Microsoft Agent Framework (MAF) adapter.

These tests detect when agent-framework changes the middleware interface in a way
that silently breaks Aevum's governance envelope. If this file fails after an
agent-framework upgrade, compare the diff carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream changes that would break this adapter:
  - agent-framework renames AgentMiddleware / FunctionMiddleware / ChatMiddleware
  - process() parameter names change (currently: context, call_next)
  - process() becomes sync (currently async)
  - MiddlewareTermination constructor signature changes
  - Dispatch changes from isinstance to duck typing (inheritance no longer needed)

IMPORTANT: All process() tests are async because MAF middleware process() methods
are async def. pytest-asyncio (asyncio_mode=auto) handles this automatically.

Notable difference from openai_agents adapter:
  - process() returns None (result flows through context.result)
  - Deny path sets context.result and raises MiddlewareTermination (not PermissionError)
  - All three are ABCs requiring inheritance (not duck typing like ADK)
  - Verified against agent-framework 1.6.0.
"""
from __future__ import annotations

import inspect

import pytest

# Skip the entire module at collection time if agent-framework is not installed.
# This guard must precede all non-stdlib imports so collection never fails.
pytest.importorskip("agent_framework", reason="agent-framework not installed")

from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402

from agent_framework import MiddlewareTermination  # noqa: E402
from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.maf import (  # noqa: E402
    AevumAgentMiddleware,
    AevumChatMiddleware,
    AevumFunctionMiddleware,
    AevumMAFMiddleware,
)


def _permit_patch() -> object:
    """Patch Cedar to allow everything — isolates adapter logic from policy."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch("aevum.core.adapters.maf.CedarPolicyEngine", **{"default.return_value": mock_engine})


def _deny_patch() -> object:
    """Patch Cedar to deny everything — isolates adapter denial path."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch("aevum.core.adapters.maf.CedarPolicyEngine", **{"default.return_value": mock_engine})


def _make_agent_context(agent_name: str = "test-agent") -> MagicMock:
    """Build a minimal AgentContext mock with agent.name attribute."""
    ctx = MagicMock()
    ctx.agent.name = agent_name
    return ctx


def _make_function_context(tool_name: str = "my_tool", arguments: object = None) -> MagicMock:
    """Build a minimal FunctionInvocationContext mock."""
    ctx = MagicMock()
    ctx.function.name = tool_name
    ctx.arguments = arguments or {}
    ctx.result = None
    return ctx


def _make_chat_context() -> MagicMock:
    """Build a minimal ChatContext mock."""
    return MagicMock()


# ── Inline-snapshot drift tests ───────────────────────────────────────────────


async def test_agent_middleware_process_passthrough() -> None:
    """
    AevumAgentMiddleware.process() must call call_next and return None.
    process() returns None — all data flows through context.result per MAF contract.
    """
    middleware = AevumAgentMiddleware(kernel=None)
    ctx = _make_agent_context("assistant")
    call_next = AsyncMock()

    result = await middleware.process(ctx, call_next)

    assert result == snapshot(None)
    call_next.assert_awaited_once()


async def test_function_middleware_allow_shape() -> None:
    """
    AevumFunctionMiddleware on Cedar allow: calls call_next and returns None.
    context.result is not modified by Aevum when Cedar permits.
    """
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("allowed_tool")
    call_next = AsyncMock()

    with _permit_patch():
        result = await middleware.process(ctx, call_next)

    assert result == snapshot(None)
    call_next.assert_awaited_once()


async def test_function_middleware_deny_shape() -> None:
    """
    AevumFunctionMiddleware on Cedar deny: MiddlewareTermination is raised
    and context.result is set to the deny dict with aevum_denied=True.
    call_next must NOT be called on deny path.
    Shape is frozen — any change to the deny response structure is a breaking change.
    """
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("dangerous_tool")
    call_next = AsyncMock()

    with _deny_patch(), pytest.raises(MiddlewareTermination):
        await middleware.process(ctx, call_next)

    call_next.assert_not_awaited()
    assert ctx.result == snapshot(
        {
            "error": "Aevum policy denied tool: dangerous_tool",
            "aevum_denied": True,
            "tool_name": "dangerous_tool",
        }
    )


async def test_chat_middleware_process_passthrough() -> None:
    """
    AevumChatMiddleware.process() must call call_next and return None.
    Chat middleware is observational only — execution always continues.
    """
    middleware = AevumChatMiddleware(kernel=None)
    ctx = _make_chat_context()
    call_next = AsyncMock()

    result = await middleware.process(ctx, call_next)

    assert result == snapshot(None)
    call_next.assert_awaited_once()


def test_middleware_parameter_names() -> None:
    """
    MAF passes middleware arguments by name — wrong parameter names cause TypeError.
    This test verifies all three process() methods accept the exact MAF names:
      process(context, call_next)
    Verified against agent-framework 1.6.0 abstract method signatures.
    """
    agent_sig = inspect.signature(AevumAgentMiddleware.process)
    agent_params = list(agent_sig.parameters.keys())
    assert agent_params == snapshot(["self", "context", "call_next"])

    func_sig = inspect.signature(AevumFunctionMiddleware.process)
    func_params = list(func_sig.parameters.keys())
    assert func_params == snapshot(["self", "context", "call_next"])

    chat_sig = inspect.signature(AevumChatMiddleware.process)
    chat_params = list(chat_sig.parameters.keys())
    assert chat_params == snapshot(["self", "context", "call_next"])


# ── Behavioral tests ──────────────────────────────────────────────────────────


def test_all_three_instantiate_with_kernel_none() -> None:
    """All three middleware can be instantiated with kernel=None."""
    assert AevumAgentMiddleware(kernel=None)._kernel is None
    assert AevumFunctionMiddleware(kernel=None)._kernel is None
    assert AevumChatMiddleware(kernel=None)._kernel is None


def test_all_three_instantiate_with_kernel() -> None:
    kernel = MagicMock()
    assert AevumAgentMiddleware(kernel=kernel)._kernel is kernel
    assert AevumFunctionMiddleware(kernel=kernel)._kernel is kernel
    assert AevumChatMiddleware(kernel=kernel)._kernel is kernel


def test_middleware_termination_is_raised_not_returned() -> None:
    """MiddlewareTermination must be raised (it is an Exception subclass)."""
    assert issubclass(MiddlewareTermination, Exception)


async def test_function_middleware_deny_does_not_call_call_next() -> None:
    """Deny path must never invoke call_next — function must not execute."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("blocked_tool")
    call_next = AsyncMock()

    with _deny_patch(), pytest.raises(MiddlewareTermination):
        await middleware.process(ctx, call_next)

    call_next.assert_not_awaited()


async def test_function_middleware_deny_contains_aevum_denied_true() -> None:
    """context.result must have aevum_denied=True (exactly True, not truthy)."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("secret_tool")
    call_next = AsyncMock()

    with _deny_patch(), pytest.raises(MiddlewareTermination):
        await middleware.process(ctx, call_next)

    assert ctx.result["aevum_denied"] is True


async def test_function_middleware_deny_contains_tool_name_in_error() -> None:
    """The deny error message must contain the tool name."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("exfil_tool")
    call_next = AsyncMock()

    with _deny_patch(), pytest.raises(MiddlewareTermination):
        await middleware.process(ctx, call_next)

    assert ctx.result["tool_name"] == "exfil_tool"
    assert "exfil_tool" in ctx.result["error"]


async def test_cedar_fail_open_does_not_terminate() -> None:
    """Cedar exception must fail-open — call_next is called despite Cedar failure."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("any_tool")
    call_next = AsyncMock()

    with patch(
        "aevum.core.adapters.maf.CedarPolicyEngine",
        **{"default.side_effect": RuntimeError("Cedar unavailable")},
    ):
        result = await middleware.process(ctx, call_next)

    call_next.assert_awaited_once()
    assert result is None


async def test_cedar_policy_error_fail_open() -> None:
    """PolicyError (is_permitted raises) also fails open."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("any_tool")
    call_next = AsyncMock()

    mock_engine = MagicMock()
    mock_engine.is_permitted.side_effect = Exception("policy eval failed")
    with patch("aevum.core.adapters.maf.CedarPolicyEngine", **{"default.return_value": mock_engine}):
        result = await middleware.process(ctx, call_next)

    call_next.assert_awaited_once()
    assert result is None


async def test_agent_middleware_kernel_failure_non_blocking() -> None:
    """Kernel record_event failure must not propagate from AevumAgentMiddleware."""
    kernel = MagicMock()
    kernel.record_event.side_effect = RuntimeError("kernel exploded")
    middleware = AevumAgentMiddleware(kernel=kernel)
    ctx = _make_agent_context()
    call_next = AsyncMock()

    result = await middleware.process(ctx, call_next)

    assert result is None
    call_next.assert_awaited_once()


async def test_function_middleware_kernel_failure_non_blocking() -> None:
    """Kernel record_event failure must not propagate from AevumFunctionMiddleware."""
    kernel = MagicMock()
    kernel.record_event.side_effect = RuntimeError("kernel exploded")
    middleware = AevumFunctionMiddleware(kernel=kernel)
    ctx = _make_function_context("my_tool")
    call_next = AsyncMock()

    with _permit_patch():
        result = await middleware.process(ctx, call_next)

    assert result is None
    call_next.assert_awaited_once()


async def test_chat_middleware_kernel_failure_non_blocking() -> None:
    """Kernel record_event failure must not propagate from AevumChatMiddleware."""
    kernel = MagicMock()
    kernel.record_event.side_effect = RuntimeError("kernel exploded")
    middleware = AevumChatMiddleware(kernel=kernel)
    ctx = _make_chat_context()
    call_next = AsyncMock()

    result = await middleware.process(ctx, call_next)

    assert result is None
    call_next.assert_awaited_once()


def test_aevum_maf_middleware_factory_returns_list() -> None:
    """AevumMAFMiddleware factory returns a list of three middleware instances."""
    result = AevumMAFMiddleware(kernel=None)

    assert isinstance(result, list)
    assert len(result) == 3
    assert isinstance(result[0], AevumAgentMiddleware)
    assert isinstance(result[1], AevumFunctionMiddleware)
    assert isinstance(result[2], AevumChatMiddleware)


def test_aevum_maf_middleware_factory_threads_kernel() -> None:
    """AevumMAFMiddleware factory passes the kernel to all three instances."""
    kernel = MagicMock()
    result = AevumMAFMiddleware(kernel=kernel)

    assert result[0]._kernel is kernel
    assert result[1]._kernel is kernel
    assert result[2]._kernel is kernel


async def test_agent_middleware_calls_cedar_for_tool_name() -> None:
    """AevumFunctionMiddleware passes the correct tool name as resource_id to Cedar."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("specific_tool")
    call_next = AsyncMock()

    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    with patch("aevum.core.adapters.maf.CedarPolicyEngine", **{"default.return_value": mock_engine}):
        await middleware.process(ctx, call_next)

    call_kwargs = mock_engine.is_permitted.call_args[1]
    assert call_kwargs["resource_id"] == "specific_tool"
    assert call_kwargs["principal_type"] == "AevumMAFAgent"
    assert call_kwargs["action"] == "tool_call"


async def test_function_middleware_tool_name_falls_back_to_unknown() -> None:
    """If context.function has no name attr, 'unknown' is used as tool_name."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = MagicMock()
    ctx.function = None  # no name attr
    ctx.arguments = {}
    ctx.result = None
    call_next = AsyncMock()

    with _permit_patch():
        result = await middleware.process(ctx, call_next)

    assert result is None
    call_next.assert_awaited_once()


# ── call_next no-args regression guards ──────────────────────────────────────


async def test_call_next_no_args_agent_middleware() -> None:
    """AevumAgentMiddleware must call call_next with no positional or keyword args."""
    middleware = AevumAgentMiddleware(kernel=None)
    ctx = _make_agent_context()
    args_received: list[object] = []

    async def mock_call_next(*args: object, **kwargs: object) -> None:
        args_received.extend(args)
        args_received.extend(kwargs.values())

    await middleware.process(ctx, mock_call_next)
    assert args_received == [], "call_next must be called with no args"


async def test_call_next_no_args_function_middleware() -> None:
    """AevumFunctionMiddleware must call call_next with no positional or keyword args."""
    middleware = AevumFunctionMiddleware(kernel=None)
    ctx = _make_function_context("some_tool")
    args_received: list[object] = []

    async def mock_call_next(*args: object, **kwargs: object) -> None:
        args_received.extend(args)
        args_received.extend(kwargs.values())

    with _permit_patch():
        await middleware.process(ctx, mock_call_next)

    assert args_received == [], "call_next must be called with no args"


async def test_call_next_no_args_chat_middleware() -> None:
    """AevumChatMiddleware must call call_next with no positional or keyword args."""
    middleware = AevumChatMiddleware(kernel=None)
    ctx = _make_chat_context()
    args_received: list[object] = []

    async def mock_call_next(*args: object, **kwargs: object) -> None:
        args_received.extend(args)
        args_received.extend(kwargs.values())

    await middleware.process(ctx, mock_call_next)
    assert args_received == [], "call_next must be called with no args"


# ── DSSAD fields in emitted receipts ─────────────────────────────────────────


async def test_agent_middleware_emits_dssad_fields() -> None:
    """agent.start and agent.end record_event payloads must include all DSSAD fields."""
    kernel = MagicMock()
    middleware = AevumAgentMiddleware(kernel=kernel)
    ctx = _make_agent_context("dssad-agent")
    call_next = AsyncMock()

    await middleware.process(ctx, call_next)

    assert kernel.record_event.call_count == 2
    for call in kernel.record_event.call_args_list:
        payload = call[1]["payload"]
        assert "handoff_type" in payload, "missing handoff_type in agent payload"
        assert "acted_on_behalf_of" in payload, "missing acted_on_behalf_of in agent payload"
        assert "maf_agent_id" in payload, "missing maf_agent_id in agent payload"
        assert "maf_middleware_type" in payload, "missing maf_middleware_type in agent payload"
        assert payload["maf_middleware_type"] == "agent"
        assert payload["handoff_type"] == "ACTIVATION"


async def test_function_middleware_emits_dssad_fields() -> None:
    """tool.start and tool.end record_event payloads must include all DSSAD fields."""
    kernel = MagicMock()
    middleware = AevumFunctionMiddleware(kernel=kernel)
    ctx = _make_function_context("dssad_tool")
    call_next = AsyncMock()

    with _permit_patch():
        await middleware.process(ctx, call_next)

    assert kernel.record_event.call_count == 2
    for call in kernel.record_event.call_args_list:
        payload = call[1]["payload"]
        assert "handoff_type" in payload, "missing handoff_type in function payload"
        assert "acted_on_behalf_of" in payload, "missing acted_on_behalf_of in function payload"
        assert "maf_agent_id" in payload, "missing maf_agent_id in function payload"
        assert "maf_middleware_type" in payload, "missing maf_middleware_type in function payload"
        assert payload["maf_middleware_type"] == "function"
        assert payload["handoff_type"] == "ACTIVATION"


async def test_chat_middleware_emits_dssad_fields() -> None:
    """llm.call record_event payload must include all DSSAD fields."""
    kernel = MagicMock()
    middleware = AevumChatMiddleware(kernel=kernel)
    ctx = _make_chat_context()
    call_next = AsyncMock()

    await middleware.process(ctx, call_next)

    kernel.record_event.assert_called_once()
    payload = kernel.record_event.call_args[1]["payload"]
    assert "handoff_type" in payload, "missing handoff_type in chat payload"
    assert "acted_on_behalf_of" in payload, "missing acted_on_behalf_of in chat payload"
    assert "maf_agent_id" in payload, "missing maf_agent_id in chat payload"
    assert "maf_middleware_type" in payload, "missing maf_middleware_type in chat payload"
    assert payload["maf_middleware_type"] == "chat"
    assert payload["handoff_type"] == "ACTIVATION"
