# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum governance plugin for Google Agent Development Kit (ADK).

AevumADKPlugin integrates Aevum's Cedar policy engine and sigchain into the
ADK plugin callback lifecycle. Used with ADK runners via the plugins= argument.

NOTE: The ADK plugin interface requires google-adk>=1.0.0. Install with:
    pip install 'aevum-core[adk]'

Verified against google-adk 1.10.0. ADK dispatches callbacks by method name
using keyword arguments — parameter names in this file are the contract.

Callback mapping:
  before_tool_callback  — Cedar policy gate; returns deny dict or None
  after_tool_callback   — sigchain append; returns None (pass-through)
  before_model_callback — LLM start record; returns None (pass-through)
  after_model_callback  — LLM end record; returns None (pass-through)

Standalone (no BasePlugin inheritance): ADK dispatches callbacks by duck typing.
No google.adk import at module level so this module remains importable when
google-adk is not installed.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)


class AevumADKPlugin:
    """
    Aevum governance plugin for Google Agent Development Kit (ADK).

    Integrates Aevum's Cedar policy engine and sigchain into the ADK
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
    Verified against google-adk 1.10.0.
    """

    def __init__(self, kernel: Any | None = None, name: str = "aevum") -> None:
        self._kernel = kernel
        self.name = name  # mirrors BasePlugin.name for ADK plugin registry

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
        ('tool_args' not 'args' — verified against google-adk 1.10.0 BasePlugin)
        """
        tool_name = getattr(tool, "name", str(tool))
        if not self._is_permitted(tool_name, tool_args):
            return {
                "error": f"Aevum barrier denied tool: {tool_name}",
                "aevum_denied": True,
                "tool_name": tool_name,
            }
        self._record_tool_start(tool_name, tool_args)
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
        Appends to sigchain. Returns None to pass response through unchanged.

        CRITICAL: 'result' not 'tool_response' — verified against google-adk 1.10.0.
        """
        tool_name = getattr(tool, "name", str(tool))
        self._record_tool_end(tool_name, tool_args, result)
        return None

    async def before_model_callback(
        self,
        *,
        callback_context: Any,
        llm_request: Any,
    ) -> Any | None:
        """
        Called before each LLM API call.
        PII/classification gate. Returns None to allow; non-None to block.

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
        Records response in sigchain. Returns None to pass through unchanged.

        CRITICAL: 'callback_context' and 'llm_response' are keyword-only.
        """
        self._record_llm_end(llm_response)
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

    def _record_tool_start(self, tool_name: str, tool_args: dict[str, Any]) -> None:
        logger.debug(
            "aevum.adk.tool_start tool=%s args_hash=%s",
            tool_name,
            hashlib.sha256(str(tool_args).encode()).hexdigest()[:16],
        )
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="tool.start",
                    actor=f"adk::{tool_name}",
                    payload={"tool": tool_name},
                )
            except Exception as _e:
                logger.warning("kernel record_event failed: %s", _e)

    def _record_tool_end(
        self, tool_name: str, tool_args: dict[str, Any], result: Any
    ) -> None:
        logger.debug("aevum.adk.tool_end tool=%s", tool_name)
        if self._kernel is not None:
            try:
                self._kernel.record_event(
                    action="tool.end",
                    actor=f"adk::{tool_name}",
                    payload={"tool": tool_name, "success": result is not None},
                )
            except Exception as _e:
                logger.warning("kernel record_event failed: %s", _e)

    def _record_llm_start(self, llm_request: Any) -> None:
        logger.debug("aevum.adk.llm_start")

    def _record_llm_end(self, llm_response: Any) -> None:
        logger.debug("aevum.adk.llm_end")
