# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum middleware for Microsoft Agent Framework (MAF).

Three middleware classes integrate Aevum governance into the MAF pipeline:
  AevumAgentMiddleware    — intercepts agent runs, records bookend events to sigchain
  AevumFunctionMiddleware — Cedar policy gate on tool calls; MiddlewareTermination on deny
  AevumChatMiddleware     — observational LLM call recording (always passes through)

Convenience factory:
  AevumMAFMiddleware(kernel)  — returns all three as a list for Agent(middleware=...)

NOTE: Requires agent-framework>=1.0.0. Install with:
    pip install 'aevum-core[maf]'

Verified against agent-framework 1.6.0. MAF dispatches by isinstance — inheritance from
AgentMiddleware / FunctionMiddleware / ChatMiddleware is required (not duck typing).
All process() methods are async (MAF contract).

Deny path: AevumFunctionMiddleware sets context.result to a deny dict containing
aevum_denied=True, then raises MiddlewareTermination to halt execution.
Cedar failures are fail-open (logged as warnings, execution continues).
Kernel record_event failures are non-blocking (logged as warnings, never propagated).
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)

# Conditional import: agent_framework must not be imported at module top level so
# this module remains importable when agent-framework is not installed.
# When absent, fallback base classes allow the subclasses to be defined normally.
try:
    from agent_framework import (  # type: ignore[import-not-found]
        AgentContext,
        ChatContext,
        FunctionInvocationContext,
        MiddlewareTermination,
    )
    from agent_framework import AgentMiddleware as _AgentMiddlewareBase
    from agent_framework import ChatMiddleware as _ChatMiddlewareBase
    from agent_framework import FunctionMiddleware as _FunctionMiddlewareBase

    _MAF_AVAILABLE = True
except ImportError:
    _MAF_AVAILABLE = False

    class _AgentMiddlewareBase:  # type: ignore[no-redef]
        pass

    class _FunctionMiddlewareBase:  # type: ignore[no-redef]
        pass

    class _ChatMiddlewareBase:  # type: ignore[no-redef]
        pass

    class AgentContext:  # type: ignore[no-redef]
        pass

    class FunctionInvocationContext:  # type: ignore[no-redef]
        pass

    class ChatContext:  # type: ignore[no-redef]
        pass

    class MiddlewareTermination(Exception):  # type: ignore[no-redef]
        pass


class AevumAgentMiddleware(_AgentMiddlewareBase):  # type: ignore[misc]
    """
    MAF AgentMiddleware: records agent session bookend events to sigchain.

    Intercepts the full agent run lifecycle (start and end). Does not block
    execution — always calls call_next. Kernel failures are non-blocking.

    Usage:
        agent = Agent(client=client, middleware=[AevumAgentMiddleware(kernel=kernel)])
    """

    def __init__(self, kernel: Any | None = None) -> None:
        self._kernel = kernel

    async def process(self, context: Any, call_next: Any) -> None:
        """
        Intercept the agent run. Records start and end events around call_next.

        CRITICAL: 'context' and 'call_next' are the exact MAF parameter names.
        Verified against agent-framework 1.6.0 AgentMiddleware.process().
        """
        agent_name = getattr(getattr(context, "agent", None), "name", "agent")
        logger.debug("aevum.maf.agent_start agent=%s", agent_name)
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="agent.start",
                    actor=f"maf::{agent_name}",
                    payload={"agent": agent_name},
                )
            except Exception as _e:  # noqa: BLE001
                logger.warning("kernel record_event (agent.start) failed: %s", _e)
        await call_next()
        logger.debug("aevum.maf.agent_end agent=%s", agent_name)
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="agent.end",
                    actor=f"maf::{agent_name}",
                    payload={"agent": agent_name},
                )
            except Exception as _e:  # noqa: BLE001
                logger.warning("kernel record_event (agent.end) failed: %s", _e)


class AevumFunctionMiddleware(_FunctionMiddlewareBase):  # type: ignore[misc]
    """
    MAF FunctionMiddleware: Cedar policy gate on every tool/function call.

    On Cedar allow: calls call_next, then records to sigchain.
    On Cedar deny: sets context.result to a deny dict and raises MiddlewareTermination.
    On Cedar exception: fail-open (logs warning, calls call_next).

    Usage:
        agent = Agent(client=client, middleware=[AevumFunctionMiddleware(kernel=kernel)])
    """

    def __init__(self, kernel: Any | None = None) -> None:
        self._kernel = kernel

    async def process(self, context: Any, call_next: Any) -> None:
        """
        Intercept the function invocation. Cedar-gates before calling call_next.

        CRITICAL: 'context' and 'call_next' are the exact MAF parameter names.
        Verified against agent-framework 1.6.0 FunctionMiddleware.process().

        Deny path: sets context.result = {aevum_denied: True, ...} then raises
        MiddlewareTermination to halt the function without calling call_next.
        """
        tool_name = getattr(getattr(context, "function", None), "name", "unknown")
        if not self._is_permitted(tool_name, context):
            deny_response = {
                "error": f"Aevum barrier denied tool: {tool_name}",
                "aevum_denied": True,
                "tool_name": tool_name,
            }
            context.result = deny_response
            raise MiddlewareTermination()
        self._record_tool_start(tool_name)
        await call_next()
        self._record_tool_end(tool_name, context)

    def _is_permitted(self, tool_name: str, context: Any) -> bool:
        try:
            engine = CedarPolicyEngine.default()
            args = getattr(context, "arguments", {})
            return engine.is_permitted(
                principal_type="AevumMAFAgent",
                principal_id="maf-agent",
                action="tool_call",
                resource_type="ToolAction",
                resource_id=tool_name,
                context={
                    "args_hash": hashlib.sha256(str(args).encode()).hexdigest(),
                },
            )
        except Exception as _e:  # noqa: BLE001
            logger.warning("Cedar eval failed (fail-open): %s", _e)
            return True

    def _record_tool_start(self, tool_name: str) -> None:
        logger.debug("aevum.maf.tool_start tool=%s", tool_name)
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="tool.start",
                    actor=f"maf::{tool_name}",
                    payload={"tool": tool_name},
                )
            except Exception as _e:  # noqa: BLE001
                logger.warning("kernel record_event (tool.start) failed: %s", _e)

    def _record_tool_end(self, tool_name: str, context: Any) -> None:
        logger.debug("aevum.maf.tool_end tool=%s", tool_name)
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="tool.end",
                    actor=f"maf::{tool_name}",
                    payload={"tool": tool_name, "success": context.result is not None},
                )
            except Exception as _e:  # noqa: BLE001
                logger.warning("kernel record_event (tool.end) failed: %s", _e)


class AevumChatMiddleware(_ChatMiddlewareBase):  # type: ignore[misc]
    """
    MAF ChatMiddleware: observational recording of LLM API calls.

    Intercepts raw model calls. Does not block — always calls call_next.
    Records the LLM call to sigchain after execution. Kernel failures are non-blocking.

    Usage:
        agent = Agent(client=client, middleware=[AevumChatMiddleware(kernel=kernel)])
    """

    def __init__(self, kernel: Any | None = None) -> None:
        self._kernel = kernel

    async def process(self, context: Any, call_next: Any) -> None:
        """
        Intercept the LLM call. Records start/end events around call_next.

        CRITICAL: 'context' and 'call_next' are the exact MAF parameter names.
        Verified against agent-framework 1.6.0 ChatMiddleware.process().
        """
        logger.debug("aevum.maf.llm_start")
        await call_next()
        logger.debug("aevum.maf.llm_end")
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="llm.call",
                    actor="maf::chat",
                    payload={},
                )
            except Exception as _e:  # noqa: BLE001
                logger.warning("kernel record_event (llm.call) failed: %s", _e)


def AevumMAFMiddleware(kernel: Any | None = None) -> list[Any]:  # noqa: N802
    """
    Convenience factory: returns all three Aevum MAF middleware as a list.

    Pass directly to Agent(middleware=...) to enable full Aevum governance:
        from aevum.core.adapters.maf import AevumMAFMiddleware
        agent = Agent(
            client=client,
            name="assistant",
            middleware=AevumMAFMiddleware(kernel=kernel),
        )

    Order: [AevumAgentMiddleware, AevumFunctionMiddleware, AevumChatMiddleware]
    """
    return [
        AevumAgentMiddleware(kernel=kernel),
        AevumFunctionMiddleware(kernel=kernel),
        AevumChatMiddleware(kernel=kernel),
    ]
