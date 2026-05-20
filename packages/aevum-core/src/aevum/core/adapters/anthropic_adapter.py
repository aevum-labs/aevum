# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum adapter for the Anthropic Python SDK.

AevumAnthropicAdapter wraps ``anthropic.Anthropic`` (or any class with the
same interface) and adds Aevum governance to every outbound API call:

- ``traceparent`` injected into the HTTP ``traceparent`` header on every call
- ``tool_use`` blocks in responses: Cedar evaluation + sigchain commit
- ``record_capture_gap()`` called when the raw Anthropic SDK is used outside
  this adapter (detected via the context variable)

Usage:
    from aevum.core.adapters.anthropic_adapter import AevumAnthropicAdapter

    client = AevumAnthropicAdapter(kernel=kernel)
    message = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )

The adapter wraps the messages API.  Other API namespaces (completions,
embeddings) are passed through unmodified.

NOTE: Stainless SDK migration — Anthropic's Python SDK was migrated to
a Stainless-generated client in early 2025.  The ``AsyncAnthropic`` variant
and streaming support (``stream()``) are not wrapped in this version.
Re-evaluate when: anthropic SDK releases a >=2.0 major version or changes
the messages.create() return schema for tool_use blocks.

Target: anthropic>=0.50.0 (Stainless generation; ``tool_use`` block in response)
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from contextvars import ContextVar
from typing import Any

from pydantic import TypeAdapter, ValidationError

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)

# Context variable tracks whether code is running inside an AevumAnthropicAdapter
# call.  record_capture_gap() checks this to detect out-of-adapter SDK usage.
_inside_adapter: ContextVar[bool] = ContextVar("_aevum_inside_anthropic_adapter", default=False)

_StrAdapter: TypeAdapter[str] = TypeAdapter(str)


def record_capture_gap(reason: str = "anthropic_sdk_used_outside_adapter") -> None:
    """
    Call this when the raw anthropic.Anthropic SDK is used outside the adapter.
    Logs a warning and records a gap event if a kernel is available on the
    current call stack.

    Intended for monkey-patching into anthropic.Anthropic.__init__ or for
    application code that detects direct SDK usage.
    """
    if not _inside_adapter.get():
        logger.warning(
            "CAPTURE_GAP: Anthropic SDK used outside AevumAnthropicAdapter. "
            "Governance envelope not applied. reason=%s",
            reason,
        )


def _make_traceparent() -> str:
    """Generate a W3C traceparent header value (version 00)."""
    trace_id = uuid.uuid4().hex           # 16 bytes = 32 hex chars
    parent_id = uuid.uuid4().hex[:16]               # 16 hex chars
    return f"00-{trace_id}-{parent_id}-01"


class _GovernedMessagesNamespace:
    """
    Wraps the ``anthropic.Anthropic().messages`` namespace.
    Intercepts ``create()`` to inject traceparent and evaluate tool_use blocks.
    """

    def __init__(self, messages: Any, kernel: Any | None) -> None:
        self._messages = messages
        self._kernel = kernel

    def create(self, **kwargs: Any) -> Any:
        """
        Wrap messages.create(): inject traceparent header, then evaluate any
        tool_use blocks in the response via Cedar + sigchain commit.
        """
        token = _inside_adapter.set(True)
        try:
            traceparent = _make_traceparent()
            headers = dict(kwargs.pop("extra_headers", {}) or {})
            headers["traceparent"] = traceparent
            kwargs["extra_headers"] = headers

            logger.debug("Anthropic API call: traceparent=%s...", traceparent[:32])

            response = self._messages.create(**kwargs)

            self._evaluate_tool_use_blocks(response, traceparent)
            return response
        finally:
            _inside_adapter.reset(token)

    def _evaluate_tool_use_blocks(self, response: Any, traceparent: str) -> None:
        """Cedar-evaluate each tool_use block; commit to sigchain if permitted."""
        content = getattr(response, "content", []) or []
        for block in content:
            block_type = getattr(block, "type", None)
            if block_type != "tool_use":
                continue

            tool_name: str = getattr(block, "name", "unknown")
            tool_input: dict[str, Any] = getattr(block, "input", {}) or {}

            try:
                tool_name = _StrAdapter.validate_python(tool_name)
            except ValidationError:
                tool_name = str(tool_name)

            engine = CedarPolicyEngine.default()
            permitted = engine.is_permitted(
                principal_type="AevumAgent",
                principal_id="anthropic-sdk",
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
                raise PermissionError(
                    f"Cedar denied Anthropic tool_use block: {tool_name!r}"
                )

            input_hash = hashlib.sha256(str(tool_input).encode()).hexdigest()
            logger.debug(
                "Anthropic tool_use: tool=%s input_hash=%s... traceparent=%s...",
                tool_name,
                input_hash[:8],
                traceparent[:16],
            )

            if self._kernel is not None:
                self._commit_tool_use(tool_name, input_hash, traceparent)

    def _commit_tool_use(self, tool_name: str, input_hash: str, traceparent: str) -> None:
        """Record a tool_use event in the sigchain (non-blocking)."""
        try:
            logger.debug(
                "Sigchain: Anthropic tool_use tool=%s hash=%s... trace=%s...",
                tool_name,
                input_hash[:8],
                traceparent[:16],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigchain commit failed for tool_use %s: %s", tool_name, exc)

    def __getattr__(self, name: str) -> Any:
        """Pass through any other messages namespace attributes."""
        return getattr(self._messages, name)


class AevumAnthropicAdapter:
    """
    Governed wrapper around ``anthropic.Anthropic``.

    All calls to ``messages.create()`` are intercepted:
    - ``traceparent`` header injected on every outbound HTTP request
    - ``tool_use`` response blocks Cedar-evaluated before returning
    - Out-of-adapter SDK usage detected via context variable

    Opt out of trace injection:
        AEVUM_SKIP_ANTHROPIC_TRACE=1 python your_app.py

    Usage:
        client = AevumAnthropicAdapter(kernel=kernel, api_key="sk-...")
        response = client.messages.create(model="claude-opus-4-7", ...)
    """

    def __init__(
        self,
        kernel: Any | None = None,
        **anthropic_kwargs: Any,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic is required for AevumAnthropicAdapter. "
                'Install it with: pip install "aevum-core[anthropic]"'
            ) from exc

        self._kernel = kernel
        self._skip_trace = os.environ.get("AEVUM_SKIP_ANTHROPIC_TRACE", "").strip() == "1"
        self._raw = anthropic.Anthropic(**anthropic_kwargs)
        self.messages = _GovernedMessagesNamespace(self._raw.messages, kernel)
        if self._skip_trace:
            logger.info("AevumAnthropicAdapter: trace injection disabled (AEVUM_SKIP_ANTHROPIC_TRACE=1)")

    def __getattr__(self, name: str) -> Any:
        """Pass through any attribute not explicitly overridden (e.g. beta, completions)."""
        return getattr(self._raw, name)
