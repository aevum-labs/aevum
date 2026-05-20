# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Traceparent round-trip integration tests for aevum-mcp.

Verifies that:
  - inject_into_meta() adds a valid W3C traceparent to _meta
  - extract_from_meta() round-trips the same value
  - AEVUM_MCP_SKIP_TRACE_INJECT=1 suppresses injection
  - The middleware records the trace_id when an incoming traceparent is present
  - Invalid traceparents are rejected by extract_from_meta()
"""
from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aevum.mcp.traceparent import (
    extract_from_meta,
    inject_into_meta,
    make_traceparent,
    should_inject,
    traceparent_to_trace_id,
)


# ── make_traceparent tests ─────────────────────────────────────────────────────

class TestMakeTraceparent:
    def test_format_version_00(self) -> None:
        tp = make_traceparent()
        assert tp.startswith("00-")

    def test_trace_id_is_32_hex(self) -> None:
        tp = make_traceparent()
        trace_id = tp.split("-")[1]
        assert len(trace_id) == 32
        assert all(c in "0123456789abcdef" for c in trace_id)

    def test_parent_id_is_16_hex(self) -> None:
        tp = make_traceparent()
        parent_id = tp.split("-")[2]
        assert len(parent_id) == 16
        assert all(c in "0123456789abcdef" for c in parent_id)

    def test_flags_are_01(self) -> None:
        tp = make_traceparent()
        assert tp.split("-")[3] == "01"

    def test_unique_per_call(self) -> None:
        assert make_traceparent() != make_traceparent()

    def test_total_format(self) -> None:
        import re
        tp = make_traceparent()
        assert re.match(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-01$", tp)


# ── inject_into_meta / extract_from_meta round-trip ───────────────────────────

class TestRoundTrip:
    def test_inject_then_extract_returns_same_traceparent(self) -> None:
        params: dict = {}
        injected = inject_into_meta(params)
        extracted = extract_from_meta(params)
        assert injected == extracted

    def test_inject_creates_meta_if_absent(self) -> None:
        params: dict = {}
        inject_into_meta(params)
        assert "_meta" in params
        assert "traceparent" in params["_meta"]

    def test_inject_preserves_existing_meta_keys(self) -> None:
        params: dict = {"_meta": {"X-Custom": "keep-me"}}
        inject_into_meta(params)
        assert params["_meta"]["X-Custom"] == "keep-me"

    def test_inject_adds_tracestate_and_baggage(self) -> None:
        params: dict = {}
        inject_into_meta(params)
        assert "tracestate" in params["_meta"]
        assert "baggage" in params["_meta"]

    def test_extract_returns_none_for_missing_meta(self) -> None:
        assert extract_from_meta({}) is None

    def test_extract_returns_none_for_non_dict_meta(self) -> None:
        assert extract_from_meta({"_meta": "not-a-dict"}) is None

    def test_extract_returns_none_for_invalid_format(self) -> None:
        params = {"_meta": {"traceparent": "invalid"}}
        assert extract_from_meta(params) is None

    def test_extract_rejects_wrong_version(self) -> None:
        params = {"_meta": {"traceparent": "01-" + "a" * 32 + "-" + "b" * 16 + "-01"}}
        assert extract_from_meta(params) is None

    def test_extract_rejects_short_trace_id(self) -> None:
        params = {"_meta": {"traceparent": "00-" + "a" * 16 + "-" + "b" * 16 + "-01"}}
        assert extract_from_meta(params) is None


# ── AEVUM_MCP_SKIP_TRACE_INJECT opt-out ───────────────────────────────────────

class TestSkipInject:
    def test_should_inject_true_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEVUM_MCP_SKIP_TRACE_INJECT", raising=False)
        assert should_inject() is True

    def test_should_inject_false_when_env_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEVUM_MCP_SKIP_TRACE_INJECT", "1")
        assert should_inject() is False

    def test_inject_skipped_when_env_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEVUM_MCP_SKIP_TRACE_INJECT", "1")
        params: dict = {}
        result = inject_into_meta(params)
        assert result == ""
        assert "_meta" not in params


# ── traceparent_to_trace_id ────────────────────────────────────────────────────

class TestTraceparentToTraceId:
    def test_extracts_trace_id(self) -> None:
        tp = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
        assert traceparent_to_trace_id(tp) == "a" * 32

    def test_returns_none_for_invalid(self) -> None:
        assert traceparent_to_trace_id("invalid") is None

    def test_returns_none_for_short_trace_id(self) -> None:
        tp = "00-" + "a" * 16 + "-" + "b" * 16 + "-01"
        assert traceparent_to_trace_id(tp) is None


# ── Middleware round-trip integration test ────────────────────────────────────

class TestMiddlewareTraceparentRoundTrip:
    """
    Verify that the governance middleware extracts an incoming traceparent
    from _meta and passes it to _record_in_sigchain as trace_id.
    """

    def _build_middleware(self) -> object:
        from aevum.mcp.middleware import build_governance_middleware_class
        cls = build_governance_middleware_class()
        kernel = MagicMock()
        return cls(kernel=kernel)

    def test_incoming_traceparent_forwarded_to_sigchain(self) -> None:
        m = self._build_middleware()
        sigchain_calls: list[dict] = []

        def mock_record(tool_name: str, in_hash: str, out_hash: str, trace_id: str = "") -> None:
            sigchain_calls.append({"tool_name": tool_name, "trace_id": trace_id})

        tp = make_traceparent()
        meta_params = {"_meta": {"traceparent": tp}}

        fake_message = SimpleNamespace(
            name="test_tool",
            arguments={},
            model_dump=lambda: meta_params,
        )
        context = SimpleNamespace(message=fake_message)

        with patch.object(m, "_evaluate_cedar", return_value=True), \
                patch.object(m, "_record_in_sigchain", side_effect=mock_record):
            asyncio.run(m.on_call_tool(context, AsyncMock(return_value="result")))

        assert len(sigchain_calls) == 1
        assert sigchain_calls[0]["trace_id"] == tp

    def test_no_incoming_traceparent_generates_outbound(self) -> None:
        m = self._build_middleware()
        sigchain_calls: list[dict] = []

        def mock_record(tool_name: str, in_hash: str, out_hash: str, trace_id: str = "") -> None:
            sigchain_calls.append({"trace_id": trace_id})

        fake_message = SimpleNamespace(
            name="test_tool",
            arguments={},
            model_dump=lambda: {},
        )
        context = SimpleNamespace(message=fake_message)

        with patch.object(m, "_evaluate_cedar", return_value=True), \
                patch.object(m, "_record_in_sigchain", side_effect=mock_record):
            asyncio.run(m.on_call_tool(context, AsyncMock(return_value="result")))

        assert len(sigchain_calls) == 1
        assert sigchain_calls[0]["trace_id"].startswith("00-")

    def test_skip_inject_still_passes_empty_trace_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AEVUM_MCP_SKIP_TRACE_INJECT", "1")
        m = self._build_middleware()
        sigchain_calls: list[dict] = []

        def mock_record(tool_name: str, in_hash: str, out_hash: str, trace_id: str = "") -> None:
            sigchain_calls.append({"trace_id": trace_id})

        fake_message = SimpleNamespace(
            name="test_tool",
            arguments={},
            model_dump=lambda: {},
        )
        context = SimpleNamespace(message=fake_message)

        with patch.object(m, "_evaluate_cedar", return_value=True), \
                patch.object(m, "_record_in_sigchain", side_effect=mock_record):
            asyncio.run(m.on_call_tool(context, AsyncMock(return_value="result")))

        assert sigchain_calls[0]["trace_id"] == ""
