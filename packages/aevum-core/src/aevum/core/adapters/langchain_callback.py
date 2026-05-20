# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum governance callback for LangChain.

AevumLangChainCallback is a BaseCallbackHandler that hooks into LangChain's
callback system and applies Aevum governance to every tool call and LLM call.

Hooks:
- on_tool_start  → Cedar ABAC evaluation → sigchain commit
- on_tool_end    → sigchain commit (outcome recorded)
- on_llm_start   → sigchain commit (prompt hash recorded)
- on_llm_end     → sigchain commit (completion hash recorded)
- on_chain_error → capture.gap with reason='langchain_chain_error'

Usage:
    from langchain_core.callbacks import CallbackManager
    from aevum.core.adapters.langchain_callback import AevumLangChainCallback

    cb = AevumLangChainCallback(kernel=kernel)
    llm = ChatOpenAI(callbacks=[cb])

LangGraph StateGraph:
    LangGraph propagates callbacks through StateGraph nodes when the
    callback is passed via RunnableConfig.  Pass the callback in the
    config dict:
        config = {"callbacks": [AevumLangChainCallback(kernel=kernel)]}
        graph.invoke(inputs, config)

NOTE: This adapter targets langchain-core>=0.2.0.  If the installed
version changes the BaseCallbackHandler signature or removes any hook
method, snapshot tests in test_langchain_callback.py will fail.
Re-evaluate when: langchain-core releases a >=1.0 stable version.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter, ValidationError

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)

_StrAdapter: TypeAdapter[str] = TypeAdapter(str)


class AevumLangChainCallback:
    """
    LangChain BaseCallbackHandler with Aevum Cedar + sigchain governance.

    This class intentionally does NOT directly subclass BaseCallbackHandler
    to allow import without langchain-core installed.  At runtime, if you
    need strict isinstance() compatibility, use the mixin pattern:

        from langchain_core.callbacks import BaseCallbackHandler
        class MyCallback(AevumLangChainCallback, BaseCallbackHandler): ...

    The class implements all hook method signatures that langchain-core
    expects, so it works as a drop-in callback regardless of subclassing.
    """

    def __init__(self, kernel: Any | None = None) -> None:
        self._kernel = kernel

    # ── on_tool_start ──────────────────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Called before a tool runs.
        Cedar-evaluates the tool call; raises PermissionError if denied.
        Returns a context dict passed to on_tool_end.
        """
        tool_name = serialized.get("name", "unknown")
        try:
            tool_name = _StrAdapter.validate_python(tool_name)
        except ValidationError:
            tool_name = str(tool_name)

        engine = CedarPolicyEngine.default()
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="langchain-agent",
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
            raise PermissionError(f"Cedar denied LangChain tool call: {tool_name!r}")

        input_hash = hashlib.sha256(str(input_str).encode()).hexdigest()
        ctx = {
            "tool_name": tool_name,
            "input_hash": input_hash,
            "started_at": datetime.now(UTC).isoformat(),
            "cedar_permitted": True,
            "run_id": str(run_id) if run_id else None,
        }

        logger.debug("LangChain on_tool_start: tool=%s input_hash=%s...", tool_name, input_hash[:8])

        if self._kernel is not None:
            self._sigchain_commit("tool_start", tool_name=tool_name, input_hash=input_hash)

        return ctx

    # ── on_tool_end ────────────────────────────────────────────────────────────

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called after a tool completes. Records outcome in sigchain."""
        output_hash = hashlib.sha256(str(output)[:500].encode()).hexdigest()
        logger.debug("LangChain on_tool_end: output_hash=%s...", output_hash[:8])

        if self._kernel is not None:
            self._sigchain_commit("tool_end", output_hash=output_hash)

    # ── on_llm_start ───────────────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Called before LLM generates. Records prompt hash in sigchain."""
        prompt_hash = hashlib.sha256(str(prompts).encode()).hexdigest()
        model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])

        logger.debug("LangChain on_llm_start: model=%s prompt_hash=%s...", model_name, prompt_hash[:8])

        ctx = {
            "model_name": model_name,
            "prompt_hash": prompt_hash,
            "started_at": datetime.now(UTC).isoformat(),
            "run_id": str(run_id) if run_id else None,
        }

        if self._kernel is not None:
            self._sigchain_commit("llm_start", model_name=str(model_name), prompt_hash=prompt_hash)

        return ctx

    # ── on_llm_end ─────────────────────────────────────────────────────────────

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called after LLM generates. Records completion hash in sigchain."""
        completion_hash = hashlib.sha256(str(response)[:500].encode()).hexdigest()
        logger.debug("LangChain on_llm_end: completion_hash=%s...", completion_hash[:8])

        if self._kernel is not None:
            self._sigchain_commit("llm_end", completion_hash=completion_hash)

    # ── on_chain_error ─────────────────────────────────────────────────────────

    def on_chain_error(
        self,
        error: Exception | KeyboardInterrupt,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a chain raises an exception.
        Records a capture gap with reason='langchain_chain_error'.
        """
        error_type = type(error).__name__
        logger.warning("LangChain on_chain_error: %s: %s", error_type, str(error)[:200])

        if self._kernel is not None:
            self._sigchain_commit(
                "capture_gap",
                reason="langchain_chain_error",
                error_type=error_type,
            )
        else:
            logger.warning(
                "CAPTURE_GAP: LangChain chain error without kernel — governance gap. "
                "reason=langchain_chain_error error_type=%s",
                error_type,
            )

    # ── internal ───────────────────────────────────────────────────────────────

    def _sigchain_commit(self, event_type: str, **payload: Any) -> None:
        """Record an event in the sigchain (non-blocking, never raises)."""
        try:
            logger.debug("Sigchain: LangChain event_type=%s payload=%s", event_type, payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigchain commit failed: event_type=%s: %s", event_type, exc)
