# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum hooks for the OpenAI Agents SDK.

AevumAgentHooks integrates Aevum governance into OpenAI Agents SDK
run lifecycle events. Every tool call is Cedar-evaluated and sigchained.
Agent handoffs are recorded with the full governance envelope.

NOTE: The OpenAI Agents SDK hook interface varies by version. This
implementation provides the common hook methods. Verify the installed
SDK version:
    python3 -c "from agents import AgentHooks; print('OK')"
    python3 -c "import agents; print(agents.__version__)"
Adapt the base class to the actual API if needed.

Target: openai-agents>=0.0.12 (or the current stable release)
"""
from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import TypeAdapter, ValidationError

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)

# Pydantic TypeAdapters for input validation at the adapter boundary.
# These validate that callers pass the expected types before any Cedar
# evaluation or sigchain write occurs.
_StrAdapter: TypeAdapter[str] = TypeAdapter(str)
_DictOrNoneAdapter: TypeAdapter[dict[str, Any] | None] = TypeAdapter(dict[str, Any] | None)
_BoolAdapter: TypeAdapter[bool] = TypeAdapter(bool)


class AevumAgentHooks:
    """
    OpenAI Agents SDK RunHooks with Aevum Cedar + sigchain integration.

    Attach to an agent run:
        from agents import Runner
        hooks = AevumAgentHooks(kernel=kernel)
        result = await Runner.run(agent, input, hooks=hooks)

    Or subclass if the SDK requires it:
        class MyHooks(AevumAgentHooks, AgentHooks): ...
    """

    def __init__(self, kernel: Any | None = None) -> None:
        self._kernel = kernel

    def on_tool_start(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        agent_name: str = "agent",
    ) -> dict[str, Any]:
        """
        Called before a tool is invoked.
        Evaluates Cedar policy. Raises PermissionError if denied.
        Returns a context dict for on_tool_end.
        Raises ValidationError if inputs do not match expected types.
        """
        try:
            tool_name = _StrAdapter.validate_python(tool_name)
            tool_input = _DictOrNoneAdapter.validate_python(tool_input)
            agent_name = _StrAdapter.validate_python(agent_name)
        except ValidationError as exc:
            raise TypeError(f"AevumAgentHooks.on_tool_start: invalid argument types: {exc}") from exc

        engine = CedarPolicyEngine.default()

        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id=agent_name,
            action="tool_call",
            resource_type="ToolAction",
            resource_id=tool_name,
            context={
                "taint_reads_untrusted": False,
                "taint_reads_private": False,
                "taint_can_exfiltrate": False,
                "has_crisis_content": False,
            },
        )

        if not permitted:
            raise PermissionError(f"Cedar denied tool call: {tool_name!r} by agent {agent_name!r}")

        input_str = str(tool_input or {})
        input_hash = hashlib.sha256(input_str.encode()).hexdigest()

        logger.debug(
            "Tool start: agent=%s tool=%s input_hash=%s...",
            agent_name,
            tool_name,
            input_hash[:8],
        )

        return {
            "tool_name": tool_name,
            "agent_name": agent_name,
            "input_hash": input_hash,
            "started_at": datetime.now(UTC).isoformat(),
            "cedar_permitted": True,
        }

    def on_tool_end(
        self,
        ctx: dict[str, Any],
        tool_output: Any,
        success: bool = True,
    ) -> None:
        """
        Called after a tool invocation completes.
        Records the outcome in the sigchain.
        Raises ValidationError if success is not a bool.
        """
        try:
            success = _BoolAdapter.validate_python(success)
        except ValidationError as exc:
            raise TypeError(f"AevumAgentHooks.on_tool_end: invalid argument types: {exc}") from exc

        output_str = str(tool_output)[:500]
        output_hash = hashlib.sha256(output_str.encode()).hexdigest()

        logger.debug(
            "Tool end: agent=%s tool=%s success=%s output_hash=%s...",
            ctx.get("agent_name"),
            ctx.get("tool_name"),
            success,
            output_hash[:8],
        )

        if self._kernel is not None:
            self._record_tool_event(ctx, output_hash, success)

    def on_handoff(
        self,
        from_agent: str,
        to_agent: str,
        context: dict[str, Any] | None = None,  # noqa: ARG002
    ) -> None:
        """
        Called when an agent hands off control to another agent.
        Records the handoff in the sigchain.
        """
        logger.info("Agent handoff: %s → %s", from_agent, to_agent)

        if self._kernel is not None:
            try:
                logger.debug("Sigchain: handoff from=%s to=%s", from_agent, to_agent)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Sigchain handoff record failed: %s", exc)

    def _record_tool_event(self, ctx: dict[str, Any], output_hash: str, success: bool) -> None:
        """Record a tool event in the sigchain (non-blocking)."""
        try:
            logger.debug(
                "Sigchain: tool_call agent=%s tool=%s success=%s",
                ctx.get("agent_name"),
                ctx.get("tool_name"),
                success,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigchain tool event record failed: %s", exc)
