# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the Google ADK AevumADKPlugin adapter.

These tests detect when google-adk changes the plugin/callback interface in
a way that silently breaks Aevum's governance envelope. If this file fails
after a google-adk upgrade, compare the diff carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream changes that would break this adapter:
  - google-adk renames BasePlugin or changes callback dispatch mechanism
  - Callback parameter names change (ADK dispatches by keyword — name = contract)
  - before_tool_callback return type changes (dict → something else for deny)
  - Callbacks become sync (currently async)
Re-evaluate when: google-adk releases a >=3.0 version with breaking changes.

IMPORTANT: All callback tests are async because ADK BasePlugin callbacks are
async def. pytest-asyncio (asyncio_mode=auto) handles this automatically.

Notable difference from openai_agents adapter:
  - before_tool_callback RETURNS a dict on deny (does not raise PermissionError)
    This is the ADK plugin contract for blocking tool execution.
  - Actual parameter names: 'tool_args' (not 'args'), 'result' (not 'tool_response')
    Verified against google-adk 2.2.0 BasePlugin source.
  - AevumADKPlugin inherits from BasePlugin (ADK 2.x requirement); falls back to
    a compatible stub when google-adk is not installed.
"""
from __future__ import annotations

import pytest

# Skip the entire module at collection time if google-adk is not installed.
# This guard must precede all non-stdlib imports so collection never fails.
pytest.importorskip("google.adk", reason="google-adk not installed")

import inspect  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.adk import AevumADKPlugin  # noqa: E402


def _permit_patch() -> object:
    """Patch Cedar to allow everything — isolates adapter logic from policy."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch("aevum.core.adapters.adk.CedarPolicyEngine", **{"default.return_value": mock_engine})


def _deny_patch() -> object:
    """Patch Cedar to deny everything — isolates adapter denial path."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch("aevum.core.adapters.adk.CedarPolicyEngine", **{"default.return_value": mock_engine})


# ── Inline-snapshot drift tests ───────────────────────────────────────────────


async def test_before_tool_callback_allow_shape() -> None:
    """
    before_tool_callback must return None when Cedar allows.
    If ADK changes the callback signature this test will fail at call time
    (TypeError on await) — surfacing the breaking change immediately.
    """
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "file_reader"
    with _permit_patch():
        result = await plugin.before_tool_callback(
            tool=mock_tool,
            tool_args={"path": "/data/test.txt"},
            tool_context=MagicMock(),
        )
    assert result == snapshot(None)


async def test_before_tool_callback_deny_shape() -> None:
    """
    before_tool_callback must return a dict with aevum_denied=True on Cedar deny.
    Shape is frozen — any change to the deny response structure is a breaking change.

    ADK contract: returning a non-None dict from before_tool_callback replaces
    the tool response (blocks execution). This differs from openai_agents which
    raises PermissionError.
    """
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "dangerous_tool"
    with _deny_patch():
        result = await plugin.before_tool_callback(
            tool=mock_tool,
            tool_args={},
            tool_context=MagicMock(),
        )
    assert result == snapshot(
        {
            "error": "Aevum barrier denied tool: dangerous_tool",
            "aevum_denied": True,
            "tool_name": "dangerous_tool",
        }
    )


async def test_after_tool_callback_passthrough_shape() -> None:
    """after_tool_callback must return None to pass response through unchanged."""
    plugin = AevumADKPlugin(kernel=None)
    result = await plugin.after_tool_callback(
        tool=MagicMock(name="tool"),
        tool_args={},
        tool_context=MagicMock(),
        result={"result": "ok"},
    )
    assert result == snapshot(None)


async def test_before_model_callback_passthrough_shape() -> None:
    """before_model_callback must return None to allow LLM call."""
    plugin = AevumADKPlugin(kernel=None)
    result = await plugin.before_model_callback(
        callback_context=MagicMock(),
        llm_request=MagicMock(),
    )
    assert result == snapshot(None)


async def test_after_model_callback_passthrough_shape() -> None:
    """after_model_callback must return None to pass response through."""
    plugin = AevumADKPlugin(kernel=None)
    result = await plugin.after_model_callback(
        callback_context=MagicMock(),
        llm_response=MagicMock(),
    )
    assert result == snapshot(None)


# ── Parameter name introspection test (Task 4) ───────────────────────────────


def test_callback_parameter_names_match_adk_spec() -> None:
    """
    ADK passes callback arguments by keyword.
    This test verifies every callback uses the exact parameter names defined
    in google.adk.plugins.BasePlugin — wrong names cause TypeError at runtime.

    Verified against google-adk 2.2.0:
      before_tool_callback: tool, tool_args, tool_context
      after_tool_callback:  tool, tool_args, tool_context, result
      before_model_callback: callback_context, llm_request
      after_model_callback:  callback_context, llm_response
    """
    plugin = AevumADKPlugin(kernel=None)

    sig = inspect.signature(plugin.before_tool_callback)
    params = list(sig.parameters.keys())
    assert "tool" in params
    assert "tool_args" in params
    assert "tool_context" in params

    sig2 = inspect.signature(plugin.after_tool_callback)
    params2 = list(sig2.parameters.keys())
    assert "tool" in params2
    assert "tool_args" in params2
    assert "tool_context" in params2
    assert "result" in params2

    sig3 = inspect.signature(plugin.before_model_callback)
    params3 = list(sig3.parameters.keys())
    assert "callback_context" in params3
    assert "llm_request" in params3

    sig4 = inspect.signature(plugin.after_model_callback)
    params4 = list(sig4.parameters.keys())
    assert "callback_context" in params4
    assert "llm_response" in params4


# ── Behavioral tests ──────────────────────────────────────────────────────────


def test_init_without_kernel() -> None:
    plugin = AevumADKPlugin(kernel=None)
    assert plugin._kernel is None


def test_init_with_kernel() -> None:
    kernel = MagicMock()
    plugin = AevumADKPlugin(kernel=kernel)
    assert plugin._kernel is kernel


def test_init_custom_name() -> None:
    plugin = AevumADKPlugin(kernel=None, name="my-plugin")
    assert plugin.name == "my-plugin"


def test_init_default_name() -> None:
    plugin = AevumADKPlugin(kernel=None)
    assert plugin.name == "aevum"


async def test_before_tool_callback_deny_returns_dict_not_raises() -> None:
    """ADK deny path returns dict — it must NOT raise PermissionError."""
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "blocked"
    with _deny_patch():
        result = await plugin.before_tool_callback(
            tool=mock_tool,
            tool_args={},
            tool_context=MagicMock(),
        )
    assert isinstance(result, dict)
    assert result["aevum_denied"] is True


async def test_before_tool_callback_deny_contains_tool_name() -> None:
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "secret_exfil"
    with _deny_patch():
        result = await plugin.before_tool_callback(
            tool=mock_tool,
            tool_args={},
            tool_context=MagicMock(),
        )
    assert result is not None
    assert result["tool_name"] == "secret_exfil"
    assert "secret_exfil" in result["error"]


async def test_after_tool_callback_does_not_raise_when_kernel_none() -> None:
    plugin = AevumADKPlugin(kernel=None)
    result = await plugin.after_tool_callback(
        tool=MagicMock(name="t"),
        tool_args={},
        tool_context=MagicMock(),
        result={"value": 1},
    )
    assert result is None


async def test_after_tool_callback_does_not_raise_when_kernel_raises() -> None:
    """Kernel failure must be non-blocking — after_tool_callback swallows it."""
    kernel = MagicMock()
    kernel.record_event.side_effect = RuntimeError("kernel exploded")
    plugin = AevumADKPlugin(kernel=kernel)
    result = await plugin.after_tool_callback(
        tool=MagicMock(name="t"),
        tool_args={},
        tool_context=MagicMock(),
        result=None,
    )
    assert result is None


async def test_record_tool_start_does_not_raise_when_kernel_none() -> None:
    plugin = AevumADKPlugin(kernel=None)
    plugin._record_tool_start("my_tool", {"a": 1}, None)


async def test_record_tool_start_does_not_raise_when_kernel_raises() -> None:
    kernel = MagicMock()
    kernel.record_event.side_effect = RuntimeError("boom")
    plugin = AevumADKPlugin(kernel=kernel)
    plugin._record_tool_start("my_tool", {}, None)


async def test_record_tool_end_does_not_raise_when_kernel_none() -> None:
    plugin = AevumADKPlugin(kernel=None)
    plugin._record_tool_end("my_tool", {}, None, {"result": "ok"})


async def test_record_tool_end_does_not_raise_when_kernel_raises() -> None:
    kernel = MagicMock()
    kernel.record_event.side_effect = RuntimeError("boom")
    plugin = AevumADKPlugin(kernel=kernel)
    plugin._record_tool_end("my_tool", {}, None, None)


def test_is_permitted_returns_true_on_cedar_exception() -> None:
    """_is_permitted must fail-open (return True) when Cedar raises."""
    plugin = AevumADKPlugin(kernel=None)
    with patch(
        "aevum.core.adapters.adk.CedarPolicyEngine",
        **{"default.side_effect": RuntimeError("Cedar unavailable")},
    ):
        assert plugin._is_permitted("any_tool", {}) is True


def test_is_permitted_returns_true_on_policy_error() -> None:
    """_is_permitted fails open on PolicyError (e.g. missing policy files)."""
    plugin = AevumADKPlugin(kernel=None)
    mock_engine = MagicMock()
    mock_engine.is_permitted.side_effect = Exception("policy eval failed")
    with patch(
        "aevum.core.adapters.adk.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    ):
        assert plugin._is_permitted("any_tool", {}) is True


async def test_before_tool_callback_calls_cedar_with_tool_name() -> None:
    """Cedar is called with the correct tool name as resource_id."""
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "specific_tool"
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    with patch("aevum.core.adapters.adk.CedarPolicyEngine", **{"default.return_value": mock_engine}):
        await plugin.before_tool_callback(
            tool=mock_tool,
            tool_args={"x": 1},
            tool_context=MagicMock(),
        )
    call_kwargs = mock_engine.is_permitted.call_args[1]
    assert call_kwargs["resource_id"] == "specific_tool"
    assert call_kwargs["principal_type"] == "AevumADKAgent"
    assert call_kwargs["action"] == "tool_call"


async def test_before_tool_callback_uses_keyword_args() -> None:
    """Confirm all callbacks can be called with pure keyword arguments."""
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "kw_tool"
    with _permit_patch():
        result = await plugin.before_tool_callback(
            tool=mock_tool,
            tool_args={},
            tool_context=MagicMock(),
        )
    assert result is None


async def test_tool_name_falls_back_to_str_when_no_name_attr() -> None:
    """If tool has no .name attribute, str(tool) is used as tool_name."""
    plugin = AevumADKPlugin(kernel=None)

    class NoNameTool:
        def __str__(self) -> str:
            return "unnamed_tool"

    with _permit_patch():
        result = await plugin.before_tool_callback(
            tool=NoNameTool(),
            tool_args={},
            tool_context=MagicMock(),
        )
    assert result is None


# ── ADK 2.x BasePlugin API tests ─────────────────────────────────────────────


def test_plugin_name_attribute_is_aevum() -> None:
    """BasePlugin sets name= in __init__; verify AevumADKPlugin passes it correctly."""
    plugin = AevumADKPlugin(kernel=None)
    assert plugin.name == "aevum"


async def test_wrong_kwarg_name_raises_type_error() -> None:
    """
    ADK dispatches callbacks by keyword — wrong parameter name causes TypeError.
    This test guards against callers using 'args' (old 1.x name) instead of 'tool_args'.
    """
    plugin = AevumADKPlugin(kernel=None)
    mock_tool = MagicMock()
    mock_tool.name = "test_tool"
    with pytest.raises(TypeError):
        await plugin.before_tool_callback(
            tool=mock_tool,
            args={"query": "test"},  # wrong: should be tool_args
            tool_context=MagicMock(),
        )


# ── DSSAD handoff field tests ─────────────────────────────────────────────────


async def test_after_tool_callback_emits_dssad_fields_to_kernel() -> None:
    """
    after_tool_callback must include DSSAD handoff fields (handoff_type,
    acted_on_behalf_of, adk_agent_name, adk_tool_name) in every kernel receipt.
    """
    kernel = MagicMock()
    plugin = AevumADKPlugin(kernel=kernel)
    mock_tool = MagicMock()
    mock_tool.name = "search_tool"

    await plugin.after_tool_callback(
        tool=mock_tool,
        tool_args={},
        tool_context=MagicMock(),
        result={"output": "found"},
    )

    assert kernel.record_event.called
    payload = kernel.record_event.call_args[1]["payload"]
    assert payload["handoff_type"] == "ACTIVATION"
    assert "acted_on_behalf_of" in payload
    assert "adk_tool_name" in payload
    assert payload["adk_tool_name"] == "search_tool"


async def test_after_model_callback_emits_dssad_fields_to_kernel() -> None:
    """after_model_callback must include DSSAD handoff fields in every kernel receipt."""
    kernel = MagicMock()
    plugin = AevumADKPlugin(kernel=kernel)

    await plugin.after_model_callback(
        callback_context=MagicMock(),
        llm_response=MagicMock(),
    )

    assert kernel.record_event.called
    payload = kernel.record_event.call_args[1]["payload"]
    assert payload["handoff_type"] == "ACTIVATION"
    assert "acted_on_behalf_of" in payload
    assert "adk_agent_name" in payload


async def test_dssad_adk_agent_name_from_tool_context() -> None:
    """adk_agent_name must be populated from tool_context.agent_name when present."""
    kernel = MagicMock()
    plugin = AevumADKPlugin(kernel=kernel)
    mock_tool = MagicMock()
    mock_tool.name = "t"
    mock_ctx = MagicMock()
    mock_ctx.agent_name = "my-adk-agent"

    await plugin.after_tool_callback(
        tool=mock_tool,
        tool_args={},
        tool_context=mock_ctx,
        result=None,
    )

    payload = kernel.record_event.call_args[1]["payload"]
    assert payload["adk_agent_name"] == "my-adk-agent"


# ── after_agent_callback tests ────────────────────────────────────────────────


async def test_after_agent_callback_returns_none() -> None:
    """after_agent_callback must return None (ambient capture, non-blocking)."""
    plugin = AevumADKPlugin(kernel=None)
    result = await plugin.after_agent_callback(
        callback_context=MagicMock(),
        llm_response=MagicMock(),
    )
    assert result is None


async def test_after_agent_callback_emits_snapshot_receipt() -> None:
    """after_agent_callback must emit a snapshot receipt with snapshot_hash."""
    kernel = MagicMock()
    plugin = AevumADKPlugin(kernel=kernel)

    await plugin.after_agent_callback(
        callback_context=MagicMock(),
        llm_response=MagicMock(),
    )

    assert kernel.record_event.called
    payload = kernel.record_event.call_args[1]["payload"]
    assert "snapshot_hash" in payload
    assert payload["handoff_type"] == "ACTIVATION"
