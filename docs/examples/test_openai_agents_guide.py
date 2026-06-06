# SPDX-License-Identifier: Apache-2.0
"""
Tests for docs/guides/openai-agents.md code examples.

Verifies that the guide's code snippets are importable and runnable against
real aevum-core internals. No OpenAI API calls are made.
"""
from __future__ import annotations

import pytest


def test_aevum_agent_hooks_importable() -> None:
    """The import block from the guide works."""
    from aevum.core.adapters.openai_agents import AevumAgentHooks

    hooks = AevumAgentHooks(kernel=None)
    assert hooks is not None


def test_openai_agents_sdk_importable() -> None:
    """openai-agents package is importable (skip if not installed)."""
    pytest.importorskip("agents")


def test_hooks_with_engine() -> None:
    """AevumAgentHooks accepts an Engine as kernel."""
    from aevum.core.engine import Engine
    from aevum.core.adapters.openai_agents import AevumAgentHooks

    engine = Engine()
    hooks = AevumAgentHooks(kernel=engine)
    assert hooks is not None


def test_on_tool_start_cedar_permit() -> None:
    """on_tool_start returns a context dict with cedar_permitted=True."""
    pytest.importorskip("cedarpy")
    from aevum.core.adapters.openai_agents import AevumAgentHooks

    hooks = AevumAgentHooks(kernel=None)
    ctx = hooks.on_tool_start(
        tool_name="web_search",
        tool_input={"query": "aevum governance"},
        agent_name="research-agent",
    )
    assert ctx["cedar_permitted"] is True
    assert "input_hash" in ctx
    assert "started_at" in ctx
    assert ctx["tool_name"] == "web_search"
    assert ctx["agent_name"] == "research-agent"


def test_full_example_from_guide() -> None:
    """The 'Full example' code block from the guide runs without error."""
    pytest.importorskip("cedarpy")
    from aevum.core.engine import Engine
    from aevum.core.adapters.openai_agents import AevumAgentHooks

    engine = Engine()
    hooks = AevumAgentHooks(kernel=engine)

    ctx = hooks.on_tool_start(
        tool_name="web_search",
        tool_input={"query": "aevum governance"},
        agent_name="research-agent",
    )
    assert ctx["cedar_permitted"] is True

    hooks.on_tool_end(ctx, tool_output="Result: aevum provides sigchain governance", success=True)
    hooks.on_handoff(from_agent="research-agent", to_agent="summary-agent")

    count = engine.ledger_count()
    assert count >= 0


def test_engine_ledger_accessible() -> None:
    """Engine remains accessible for sigchain inspection after hooks init."""
    from aevum.core.engine import Engine
    from aevum.core.adapters.openai_agents import AevumAgentHooks

    engine = Engine()
    hooks = AevumAgentHooks(kernel=engine)
    assert hooks is not None
    count = engine.ledger_count()
    assert count >= 0
