"""
Tests for AgentComplication base class.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from aevum.sdk.agent import AUTONOMY_THRESHOLDS, AgentComplication


class _L1Agent(AgentComplication):
    name = "test-l1-agent"
    version = "0.1.0"
    capabilities = ["l1-test"]
    autonomy_level = 1

    async def _run(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
        return {"result": "done"}


class _L3Agent(AgentComplication):
    name = "test-l3-agent"
    version = "0.1.0"
    capabilities = ["l3-test"]
    autonomy_level = 3

    async def _run(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
        return {"result": "done"}


class _L5Agent(AgentComplication):
    name = "test-l5-agent"
    version = "0.1.0"
    capabilities = ["l5-test"]
    autonomy_level = 5

    async def _run(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
        return {"result": "done"}


def _ctx() -> dict[str, Any]:
    return {"subject_ids": [], "purpose": "test", "actor": "test-actor"}


class TestAutonomyThresholds:
    def test_threshold_values(self) -> None:
        assert AUTONOMY_THRESHOLDS[1] == 1
        assert AUTONOMY_THRESHOLDS[2] == 3
        assert AUTONOMY_THRESHOLDS[3] == 5
        assert AUTONOMY_THRESHOLDS[4] == 10
        assert AUTONOMY_THRESHOLDS[5] is None

    def test_invalid_autonomy_level_raises(self) -> None:
        with pytest.raises(TypeError, match="autonomy_level"):
            class BadAgent(AgentComplication):
                name = "bad"
                version = "0.1.0"
                capabilities = ["bad"]
                autonomy_level = 6  # Invalid

                async def _run(self, ctx: Any, payload: dict[str, Any]) -> dict[str, Any]:
                    return {}


class TestL1Agent:
    @pytest.mark.asyncio
    async def test_first_action_triggers_review(self) -> None:
        agent = _L1Agent()
        callback = MagicMock()
        agent.set_review_callback(callback)

        await agent.run(_ctx(), {})
        assert callback.called, "L1: first action must trigger review"
        assert agent.consecutive_actions == 1

    @pytest.mark.asyncio
    async def test_consecutive_actions_increment(self) -> None:
        agent = _L1Agent()
        agent.set_review_callback(MagicMock())
        await agent.run(_ctx(), {})
        await agent.run(_ctx(), {})
        assert agent.consecutive_actions == 2

    def test_reset_clears_counter(self) -> None:
        agent = _L1Agent()
        agent._consecutive_actions = 5
        agent.reset_consecutive_actions()
        assert agent.consecutive_actions == 0


class TestL3Agent:
    @pytest.mark.asyncio
    async def test_first_four_actions_no_review(self) -> None:
        agent = _L3Agent()
        callback = MagicMock()
        agent.set_review_callback(callback)

        for _ in range(4):
            await agent.run(_ctx(), {})

        assert callback.call_count == 0, "L3: first 4 actions must not trigger review"

    @pytest.mark.asyncio
    async def test_fifth_action_triggers_review(self) -> None:
        agent = _L3Agent()
        callback = MagicMock()
        agent.set_review_callback(callback)

        for _ in range(5):
            await agent.run(_ctx(), {})

        assert callback.call_count == 1, "L3: action 5 must trigger review"

    @pytest.mark.asyncio
    async def test_no_callback_no_error(self) -> None:
        """Agent runs safely without a review callback injected."""
        agent = _L3Agent()
        # No set_review_callback called
        for _ in range(6):
            await agent.run(_ctx(), {})
        # Should not raise


class TestL5Agent:
    @pytest.mark.asyncio
    async def test_l5_never_triggers_review(self) -> None:
        agent = _L5Agent()
        callback = MagicMock()
        agent.set_review_callback(callback)

        for _ in range(20):
            await agent.run(_ctx(), {})

        assert callback.call_count == 0, "L5: should never trigger review"


class TestAgentManifest:
    def test_manifest_includes_agent_fields(self) -> None:
        agent = _L3Agent()
        m = agent.manifest()
        assert "agent" in m
        assert m["agent"]["autonomy_level"] == 3
        assert m["agent"]["consecutive_action_threshold"] == 5

    def test_manifest_schema_version(self) -> None:
        assert _L3Agent().manifest()["schema_version"] == "1.0"


class TestThreadSafety:
    @pytest.mark.asyncio
    async def test_concurrent_actions_correct_count(self) -> None:
        agent = _L3Agent()
        callback = MagicMock()
        agent.set_review_callback(callback)

        await asyncio.gather(*[agent.run(_ctx(), {}) for _ in range(10)])
        assert agent.consecutive_actions == 10
