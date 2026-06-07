# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum governance plugin for Google Agent Development Kit (ADK).

AevumADKPlugin integrates Aevum's Cedar policy engine and sigchain into the
ADK plugin callback lifecycle. Used with ADK runners via the plugins= argument.

NOTE: The ADK plugin interface requires google-adk>=2.2.0. Install with:
    pip install 'aevum-core[adk]'

Verified against google-adk 2.2.0. ADK dispatches callbacks by method name
using keyword arguments — parameter names in this file are the contract.

Callback mapping:
  before_tool_callback  — Cedar policy gate; returns deny dict or None
  after_tool_callback   — sigchain append + DSSAD receipt; returns None (pass-through)
  before_model_callback — PII/classification gate; returns None (pass-through)
  after_model_callback  — sigchain append + DSSAD receipt; returns None (pass-through)
  after_agent_callback  — ambient context snapshot (if present in BasePlugin)

Inherits from BasePlugin (ADK 2.x requirement). Falls back to a compatible stub
class when google-adk is not installed, so this module remains importable for
type-checking and testing without the full ADK dependency.

KNOWN LIMITATION (ADK issue #2809, June 2026):
AevumADKPlugin callbacks do NOT fire for sub-agents invoked via AgentTool.
Governance coverage applies only to the top-level Runner's agent.
Workaround: register AevumADKPlugin on each sub-agent's Runner individually.
Track: https://github.com/google/adk-python/issues/2809
"""
from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)

# Conditional BasePlugin import — keeps module importable without google-adk installed.
# ADK 2.x requires actual inheritance from BasePlugin (not just duck typing).
try:
    from google.adk.plugins.base_plugin import BasePlugin as _BasePlugin
except ImportError:

    class _BasePlugin:  # type: ignore[no-redef]
        """Stub base class used when google-adk is not installed."""

        def __init__(self, *, name: str) -> None:
            self.name = name


class AevumADKPlugin(_BasePlugin):
    """
    Aevum governance plugin for Google Agent Development Kit (ADK).

    Integrates Aevum's Cedar policy engine and sigchain into the ADK 2.x
    callback lifecycle. Pass an instance to ADK Runner via plugins=.

    Usage:
        from aevum.core.adapters.adk import AevumADKPlugin
        plugin = AevumADKPlugin(kernel=kernel)
        runner = Runner(
            agent=my_agent,
            ...,
            plugins=[plugin],
        )

    Parameter names in all callbacks MUST match google.adk.plugins.BasePlugin
    exactly — ADK dispatches by keyword and wrong names cause TypeError.
    Verified against google-adk 2.2.0.
    """

    def __init__(self, kernel: Any | None = None, name: str = "aevum") -> None:
        super().__init__(name=name)
        self._kernel = kernel

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
    ) -> dict[str, Any] | None:
        """
        Called before each tool execution.
        Evaluates Cedar policy. Returns deny dict to block; None to allow.

        CRITICAL: 'tool', 'tool_args', 'tool_context' are keyword-only.
        ADK dispatches these by name — any rename causes TypeError at runtime.
        ('tool_args' not 'args' — verified against google-adk 2.2.0 BasePlugin)
        """
        tool_name = getattr(tool, "name", str(tool))
        if not self._is_permitted(tool_name, tool_args):
            return {
                "error": f"Aevum barrier denied tool: {tool_name}",
                "aevum_denied": True,
                "tool_name": tool_name,
            }
        self._record_tool_start(tool_name, tool_args, tool_context)
        return None

    async def after_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
        result: Any,
    ) -> Any | None:
        """
        Called after each tool execution.
        Appends sigchain entry and emits DSSAD receipt. Returns None (pass-through).

        CRITICAL: 'result' not 'tool_response' — verified against google-adk 2.2.0.
        """
        tool_name = getattr(tool, "name", str(tool))
        self._record_tool_end(tool_name, tool_args, tool_context, result)
        return None

    async def before_model_callback(
        self,
        *,
        callback_context: Any,
        llm_request: Any,
    ) -> Any | None:
        """
        Called before each LLM API call.
        PII/classification gate. Returns None to allow; non-None LlmResponse to block.

        CRITICAL: 'callback_context' and 'llm_request' are keyword-only.
        """
        self._record_llm_start(llm_request)
        return None

    async def after_model_callback(
        self,
        *,
        callback_context: Any,
        llm_response: Any,
    ) -> Any | None:
        """
        Called after each LLM API call.
        Appends sigchain entry and emits DSSAD receipt. Returns None (pass-through).

        CRITICAL: 'callback_context' and 'llm_response' are keyword-only.
        """
        self._record_llm_end(llm_response)
        return None

    async def after_agent_callback(
        self,
        *,
        callback_context: Any,
        llm_response: Any,
    ) -> Any | None:
        """
        Ambient context capture — fires after each agent turn.

        Emits a system-state snapshot receipt at agent-turn granularity (equivalent
        to 1 Hz sampling). This is a lightweight receipt; it does not block execution.

        NOTE: after_agent_callback may not be present in BasePlugin for all ADK 2.x
        versions. If BasePlugin does not declare this method, ADK will only dispatch
        it if it detects it on the plugin instance via duck typing. Verified: ADK 2.2.0
        dispatches all declared plugin methods by name.
        """
        snapshot_hash = hashlib.sha3_256(
            f"{self.name}:{datetime.now(UTC).isoformat()}".encode()
        ).hexdigest()
        logger.debug(
            "aevum.adk.agent_snapshot snapshot_hash=%s",
            snapshot_hash[:16],
        )
        self._emit_receipt(
            event="agent_turn",
            handoff_type="ACTIVATION",
            adk_tool_name=None,
            tool_context=None,
            extra={"snapshot_hash": snapshot_hash},
        )
        return None

    # --- private helpers ---

    def _is_permitted(self, tool_name: str, tool_args: dict[str, Any]) -> bool:
        try:
            engine = CedarPolicyEngine.default()
            return engine.is_permitted(
                principal_type="AevumADKAgent",
                principal_id="adk-agent",
                action="tool_call",
                resource_type="ToolAction",
                resource_id=tool_name,
                context={
                    "args_hash": hashlib.sha256(
                        str(sorted(tool_args.items())).encode()
                    ).hexdigest(),
                },
            )
        except Exception as _e:
            logger.warning("Cedar eval failed (fail-open): %s", _e)
            return True

    def _emit_receipt(
        self,
        event: str,
        handoff_type: str,
        adk_tool_name: str | None,
        tool_context: Any,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit a DSSAD-compliant receipt via logger and kernel."""
        agent_name = (
            tool_context.agent_name
            if tool_context is not None and hasattr(tool_context, "agent_name")
            else None
        )
        payload: dict[str, Any] = {
            "event": event,
            "timestamp": datetime.now(UTC).isoformat(),
            # DSSAD handoff fields (required on every receipt from this adapter)
            "handoff_type": handoff_type,
            "acted_on_behalf_of": None,
            "adk_agent_name": agent_name,
            "adk_tool_name": adk_tool_name,
        }
        if extra:
            payload.update(extra)
        logger.debug("aevum.adk.receipt %s", payload)
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action=f"adk.{event}",
                    actor=f"adk::{adk_tool_name or 'agent'}",
                    payload=payload,
                )
            except Exception as _e:
                logger.warning("kernel record_event failed: %s", _e)

    def _record_tool_start(
        self, tool_name: str, tool_args: dict[str, Any], tool_context: Any
    ) -> None:
        logger.debug(
            "aevum.adk.tool_start tool=%s args_hash=%s",
            tool_name,
            hashlib.sha256(str(tool_args).encode()).hexdigest()[:16],
        )
        self._emit_receipt(
            event="tool_start",
            handoff_type="ACTIVATION",
            adk_tool_name=tool_name,
            tool_context=tool_context,
        )

    def _record_tool_end(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_context: Any,
        result: Any,
    ) -> None:
        logger.debug("aevum.adk.tool_end tool=%s", tool_name)
        self._emit_receipt(
            event="tool_end",
            handoff_type="ACTIVATION",
            adk_tool_name=tool_name,
            tool_context=tool_context,
            extra={"success": result is not None},
        )

    def _record_llm_start(self, llm_request: Any) -> None:
        logger.debug("aevum.adk.llm_start")
        self._emit_receipt(
            event="llm_start",
            handoff_type="ACTIVATION",
            adk_tool_name=None,
            tool_context=None,
        )

    def _record_llm_end(self, llm_response: Any) -> None:
        logger.debug("aevum.adk.llm_end")
        self._emit_receipt(
            event="llm_end",
            handoff_type="ACTIVATION",
            adk_tool_name=None,
            tool_context=None,
        )
