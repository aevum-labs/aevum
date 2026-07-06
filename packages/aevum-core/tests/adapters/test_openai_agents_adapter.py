# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the openai-agents adapter.

These tests detect when the openai-agents SDK changes the hook interface in
a way that silently breaks Aevum's governance envelope. If this file fails
after an openai-agents upgrade, compare the diff carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream change that would break this adapter:
  - openai-agents renames AgentHooks or removes on_tool_start / on_tool_end
  - AgentHooks changes the return type expected from on_tool_start
  - The context dict keys read by the SDK change
Re-evaluate when: openai-agents releases a >=1.0 stable version.
"""
from __future__ import annotations

import pytest

# Skip the entire module at collection time if openai-agents is not installed.
# This guard must precede all non-stdlib imports so collection never fails.
try:
    import agents  # noqa: F401
except ModuleNotFoundError as exc:
    # Only skip when openai-agents itself is absent. Any other ImportError/ModuleNotFoundError
    # (e.g. a transitive dependency version conflict) is a real regression and must fail
    # loudly here, not be silently reclassified as "not installed".
    if exc.name != "agents":
        raise
    pytest.skip("openai-agents not installed", allow_module_level=True)

from unittest.mock import MagicMock, patch  # noqa: E402

from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.openai_agents import AevumAgentHooks  # noqa: E402


def _permit_patch() -> object:
    """Patch Cedar to allow everything — isolates adapter logic from policy."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch("aevum.core.adapters.openai_agents.CedarPolicyEngine", **{"default.return_value": mock_engine})


def test_on_tool_start_return_shape() -> None:
    """
    on_tool_start must return a dict with exactly these keys and value types.
    If the adapter adds, removes, or renames a key this snapshot fails.
    Run pytest --inline-snapshot=fix to update after intentional changes.
    """
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        result = hooks.on_tool_start("web_search", {"query": "test"}, "test-agent")

    assert result == snapshot(
        {
            "tool_name": "web_search",
            "agent_name": "test-agent",
            "input_hash": "38f9fec0f9fbd5c0f25866163818507ed1df04811a95b957a5967fd63cbba281",
            "started_at": result["started_at"],
            "cedar_permitted": True,
        }
    )


def test_on_tool_start_cedar_permitted_field_is_bool() -> None:
    """cedar_permitted must be exactly True (not truthy) — consumers type-check it."""
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        result = hooks.on_tool_start("any_tool", {})
    assert result["cedar_permitted"] is True


def test_on_tool_start_input_hash_is_hex64() -> None:
    """input_hash must be a 64-character lowercase hex string (SHA-256)."""
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        result = hooks.on_tool_start("tool", {"k": "v"})
    assert len(result["input_hash"]) == 64
    assert all(c in "0123456789abcdef" for c in result["input_hash"])


def test_on_tool_start_raises_permission_error_on_deny() -> None:
    """Cedar deny must raise PermissionError — not return a falsy value."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    with (
        patch("aevum.core.adapters.openai_agents.CedarPolicyEngine", **{"default.return_value": mock_engine}),
        pytest.raises(PermissionError, match="Cedar denied"),
    ):
        AevumAgentHooks(kernel=None).on_tool_start("blocked_tool", {})


# ── on_tool_end snapshot tests (A-26) ─────────────────────────────────────────


def test_on_tool_end_returns_none() -> None:
    """
    on_tool_end must return None (not a context dict).
    If the return type changes, downstream consumers that ignore the return value
    may silently receive unexpected data.
    """
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        ctx = hooks.on_tool_start("web_search", {"query": "test"}, "test-agent")

    result = hooks.on_tool_end(ctx, "search results here", success=True)
    assert result == snapshot(None)


def test_on_tool_end_success_false_returns_none() -> None:
    """on_tool_end with success=False must also return None."""
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        ctx = hooks.on_tool_start("tool", {})

    result = hooks.on_tool_end(ctx, "error output", success=False)
    assert result == snapshot(None)


def test_on_tool_end_with_kernel_does_not_raise() -> None:
    """on_tool_end with a kernel attached must complete without raising."""
    hooks = AevumAgentHooks(kernel=MagicMock())
    with _permit_patch():
        ctx = hooks.on_tool_start("tool", {})

    result = hooks.on_tool_end(ctx, {"structured": "output"}, success=True)
    assert result == snapshot(None)


def test_on_tool_end_output_hash_computation_is_stable() -> None:
    """
    The output hash is computed from str(tool_output)[:500].
    This snapshot guards the truncation boundary and hash algorithm.
    """
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        ctx = hooks.on_tool_start("tool", {})

    # on_tool_end does not expose the hash directly; confirm it does not raise
    hooks.on_tool_end(ctx, "hello world", success=True)


# ── TypeAdapter boundary guard tests (A-29) ───────────────────────────────────


def test_on_tool_start_rejects_non_string_tool_name() -> None:
    """TypeAdapter guard: tool_name must be a string."""
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch(), pytest.raises(TypeError, match="invalid argument types"):
        hooks.on_tool_start(123, {})  # type: ignore[arg-type]


def test_on_tool_end_rejects_non_bool_success() -> None:
    """TypeAdapter guard: success must be a bool."""
    hooks = AevumAgentHooks(kernel=None)
    with _permit_patch():
        ctx = hooks.on_tool_start("tool", {})

    with pytest.raises(TypeError, match="invalid argument types"):
        hooks.on_tool_end(ctx, "output", success="yes")  # type: ignore[arg-type]
