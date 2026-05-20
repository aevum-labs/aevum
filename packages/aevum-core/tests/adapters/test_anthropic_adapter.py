# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the Anthropic SDK adapter.

These tests detect when the anthropic SDK changes the messages.create()
response schema (especially tool_use blocks) in a way that silently breaks
Aevum's governance envelope.  If this file fails after an anthropic upgrade,
compare the diff carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream change that would break this adapter:
  - anthropic renames ``type="tool_use"`` blocks to a different type string
  - The ``name`` or ``input`` field is removed from tool_use content blocks
  - messages.create() stops accepting ``extra_headers``
  - Stainless SDK migration changes the messages namespace structure
Re-evaluate when: anthropic releases a >=2.0 major version.
"""
from __future__ import annotations

import pytest

pytest.importorskip("anthropic", reason="anthropic not installed")

import os  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.anthropic_adapter import (  # noqa: E402
    AevumAnthropicAdapter,
    _GovernedMessagesNamespace,
    _make_traceparent,
    record_capture_gap,
)


def _permit_patch() -> object:
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch(
        "aevum.core.adapters.anthropic_adapter.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    )


def _deny_patch() -> object:
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch(
        "aevum.core.adapters.anthropic_adapter.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    )


def _mock_raw_client() -> MagicMock:
    """Build a minimal mock anthropic.Anthropic client."""
    raw = MagicMock()
    raw.messages = MagicMock()
    return raw


def _tool_use_response(tool_name: str = "calculator", tool_input: dict = {"op": "add"}) -> MagicMock:
    """Build a fake messages.create() response containing one tool_use block."""
    block = SimpleNamespace(type="tool_use", name=tool_name, input=tool_input)
    response = MagicMock()
    response.content = [block]
    return response


# ── traceparent format tests ───────────────────────────────────────────────────


def test_traceparent_format() -> None:
    """
    traceparent must match W3C format: 00-{32hex}-{16hex}-01
    """
    tp = _make_traceparent()
    parts = tp.split("-")
    assert parts == snapshot(["00", parts[1], parts[2], "01"])
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16
    assert all(c in "0123456789abcdef" for c in parts[1] + parts[2])


def test_traceparent_unique_per_call() -> None:
    """Each call to _make_traceparent must return a unique value."""
    assert _make_traceparent() != _make_traceparent()


# ── traceparent injection tests ────────────────────────────────────────────────


def test_messages_create_injects_traceparent_header() -> None:
    """
    messages.create() must inject a ``traceparent`` key into extra_headers.
    This is the contract that ensures every Anthropic API call is traceable.
    """
    raw = _mock_raw_client()
    raw.messages.create.return_value = MagicMock(content=[])

    ns = _GovernedMessagesNamespace(raw.messages, kernel=None)
    with _permit_patch():
        ns.create(model="claude-opus-4-7", max_tokens=100, messages=[])

    call_kwargs = raw.messages.create.call_args[1]
    assert "extra_headers" in call_kwargs
    assert "traceparent" in call_kwargs["extra_headers"]

    tp = call_kwargs["extra_headers"]["traceparent"]
    assert tp.startswith("00-")
    assert len(tp) == len("00-" + "x" * 32 + "-" + "x" * 16 + "-01")


def test_messages_create_preserves_existing_extra_headers() -> None:
    """Existing extra_headers must be preserved alongside the injected traceparent."""
    raw = _mock_raw_client()
    raw.messages.create.return_value = MagicMock(content=[])

    ns = _GovernedMessagesNamespace(raw.messages, kernel=None)
    with _permit_patch():
        ns.create(
            model="claude-opus-4-7",
            max_tokens=100,
            messages=[],
            extra_headers={"X-Custom": "value"},
        )

    headers = raw.messages.create.call_args[1]["extra_headers"]
    assert headers["X-Custom"] == snapshot("value")
    assert "traceparent" in headers


# ── tool_use block evaluation tests ───────────────────────────────────────────


def test_tool_use_block_cedar_permit_passes() -> None:
    """Cedar permit on tool_use block: messages.create() returns normally."""
    raw = _mock_raw_client()
    raw.messages.create.return_value = _tool_use_response("web_search", {"query": "test"})

    ns = _GovernedMessagesNamespace(raw.messages, kernel=None)
    with _permit_patch():
        response = ns.create(model="claude-opus-4-7", max_tokens=100, messages=[])

    assert response is not None


def test_tool_use_block_cedar_deny_raises_permission_error() -> None:
    """Cedar deny on tool_use block: must raise PermissionError."""
    raw = _mock_raw_client()
    raw.messages.create.return_value = _tool_use_response("dangerous_tool")

    ns = _GovernedMessagesNamespace(raw.messages, kernel=None)
    with _deny_patch(), pytest.raises(PermissionError, match="Cedar denied Anthropic tool_use"):
        ns.create(model="claude-opus-4-7", max_tokens=100, messages=[])


def test_no_tool_use_blocks_no_cedar_call() -> None:
    """When there are no tool_use blocks, Cedar must not be called."""
    raw = _mock_raw_client()
    text_block = SimpleNamespace(type="text", text="hello")
    raw.messages.create.return_value = MagicMock(content=[text_block])

    mock_engine = MagicMock()
    ns = _GovernedMessagesNamespace(raw.messages, kernel=None)
    with patch(
        "aevum.core.adapters.anthropic_adapter.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    ):
        ns.create(model="claude-opus-4-7", max_tokens=100, messages=[])

    mock_engine.is_permitted.assert_not_called()


def test_tool_use_block_name_captured_correctly() -> None:
    """Cedar must receive exactly the tool name from the response block."""
    raw = _mock_raw_client()
    raw.messages.create.return_value = _tool_use_response("exact_tool_name", {})

    captured: list[str] = []
    mock_engine = MagicMock()
    mock_engine.is_permitted.side_effect = lambda **kw: captured.append(kw["resource_id"]) or True

    ns = _GovernedMessagesNamespace(raw.messages, kernel=None)
    with patch(
        "aevum.core.adapters.anthropic_adapter.CedarPolicyEngine",
        **{"default.return_value": mock_engine},
    ):
        ns.create(model="claude-opus-4-7", max_tokens=100, messages=[])

    assert captured == snapshot(["exact_tool_name"])


# ── AevumAnthropicAdapter integration tests ───────────────────────────────────


def test_adapter_messages_namespace_is_governed() -> None:
    """adapter.messages must be a _GovernedMessagesNamespace instance."""
    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value = _mock_raw_client()
        adapter = AevumAnthropicAdapter(kernel=None, api_key="test")

    assert isinstance(adapter.messages, _GovernedMessagesNamespace)


def test_adapter_passthrough_for_other_attrs() -> None:
    """Attributes not overridden (e.g. beta) must pass through to the raw client."""
    raw = _mock_raw_client()
    raw.beta = "beta-ns"

    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value = raw
        adapter = AevumAnthropicAdapter(kernel=None, api_key="test")

    assert adapter.beta == snapshot("beta-ns")


def test_adapter_skip_trace_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """AEVUM_SKIP_ANTHROPIC_TRACE=1 must set _skip_trace=True on the adapter."""
    monkeypatch.setenv("AEVUM_SKIP_ANTHROPIC_TRACE", "1")
    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value = _mock_raw_client()
        adapter = AevumAnthropicAdapter(kernel=None, api_key="test")

    assert adapter._skip_trace is snapshot(True)


# ── record_capture_gap tests ───────────────────────────────────────────────────


def test_record_capture_gap_logs_outside_adapter(caplog: pytest.LogCaptureFixture) -> None:
    """record_capture_gap() must log a WARNING when called outside the adapter."""
    import logging

    with caplog.at_level(logging.WARNING, logger="aevum.core.adapters.anthropic_adapter"):
        record_capture_gap("test_reason")

    assert any("CAPTURE_GAP" in r.message for r in caplog.records)


def test_record_capture_gap_silent_inside_adapter() -> None:
    """record_capture_gap() must not log when called inside an active adapter call."""
    from aevum.core.adapters.anthropic_adapter import _inside_adapter

    token = _inside_adapter.set(True)
    try:
        import logging
        import io
        handler = logging.StreamHandler(io.StringIO())
        logger = logging.getLogger("aevum.core.adapters.anthropic_adapter")
        logger.addHandler(handler)
        record_capture_gap("should_be_silent")
        output = handler.stream.getvalue()
        assert "CAPTURE_GAP" not in output
    finally:
        _inside_adapter.reset(token)
