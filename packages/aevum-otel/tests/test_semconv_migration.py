# SPDX-License-Identifier: Apache-2.0
"""Tests for OTel GenAI semconv dual-emit migration.

Verifies that gen_ai.provider.name is always present,
gen_ai.system is present by default (backward compat),
and gen_ai.system is absent when opt-in is set.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch


def _make_span() -> MagicMock:
    span = MagicMock()
    span._attributes: dict = {}

    def set_attr(k, v):
        span._attributes[k] = v

    span.set_attribute.side_effect = set_attr
    return span


def test_set_genai_provider_always_emits_new_name() -> None:
    from aevum.otel.bridge import _set_genai_provider

    span = _make_span()
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("OTEL_SEMCONV_STABILITY_OPT_IN", None)
        _set_genai_provider(span, "anthropic")
    assert span._attributes.get("gen_ai.provider.name") == "anthropic"


def test_set_genai_provider_emits_system_by_default() -> None:
    from aevum.otel.bridge import _set_genai_provider

    span = _make_span()
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("OTEL_SEMCONV_STABILITY_OPT_IN", None)
        _set_genai_provider(span, "openai")
    assert span._attributes.get("gen_ai.system") == "openai"
    assert span._attributes.get("gen_ai.provider.name") == "openai"


def test_set_genai_provider_omits_system_when_opted_in() -> None:
    from aevum.otel.bridge import _set_genai_provider

    span = _make_span()
    with patch.dict(
        os.environ,
        {"OTEL_SEMCONV_STABILITY_OPT_IN": "gen_ai_latest_experimental"},
    ):
        _set_genai_provider(span, "anthropic")
    assert "gen_ai.system" not in span._attributes
    assert span._attributes.get("gen_ai.provider.name") == "anthropic"


def test_set_genai_provider_case_insensitive_opt_in() -> None:
    from aevum.otel.bridge import _set_genai_provider

    span = _make_span()
    with patch.dict(
        os.environ,
        {"OTEL_SEMCONV_STABILITY_OPT_IN": "GEN_AI_LATEST_EXPERIMENTAL"},
    ):
        _set_genai_provider(span, "anthropic")
    assert "gen_ai.system" not in span._attributes
    assert span._attributes.get("gen_ai.provider.name") == "anthropic"


def test_ingest_allowlist_includes_provider_name() -> None:
    from aevum.core.functions.ingest import _OTEL_GENAI_KEYS

    assert "gen_ai.provider.name" in _OTEL_GENAI_KEYS
    assert "gen_ai.system" in _OTEL_GENAI_KEYS  # backward compat


def test_ingest_allowlist_includes_agent_keys() -> None:
    from aevum.core.functions.ingest import _OTEL_GENAI_KEYS

    assert "gen_ai.agent.name" in _OTEL_GENAI_KEYS
    assert "gen_ai.agent.id" in _OTEL_GENAI_KEYS


def test_span_name_format() -> None:
    """Span names must follow '{operation} {model}' format."""
    import aevum.otel.bridge as b

    if hasattr(b, "_make_span_name"):
        name = b._make_span_name("chat", "claude-sonnet-4-6")
        assert name == "chat claude-sonnet-4-6"
        assert "gen_ai" not in name


def test_bridge_emits_provider_name_on_span(monkeypatch) -> None:
    """bridge.on_event always emits gen_ai.provider.name = 'aevum'."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from aevum.otel import AevumOTelBridge

    monkeypatch.delenv("OTEL_SEMCONV_STABILITY_OPT_IN", raising=False)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    bridge = AevumOTelBridge(service_name="test", tracer_provider=provider)

    event = MagicMock()
    event.audit_id.return_value = "urn:aevum:audit:x"
    event.event_type = "ingest.accepted"
    event.actor = "test-actor"
    event.sequence = 1
    event.episode_id = None

    bridge.on_event(event)

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attrs = dict(spans[0].attributes or {})
    assert attrs.get("gen_ai.provider.name") == "aevum"


def test_bridge_emits_system_by_default(monkeypatch) -> None:
    """bridge.on_event emits gen_ai.system by default for backward compat."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from aevum.otel import AevumOTelBridge

    monkeypatch.delenv("OTEL_SEMCONV_STABILITY_OPT_IN", raising=False)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    bridge = AevumOTelBridge(service_name="test", tracer_provider=provider)

    event = MagicMock()
    event.audit_id.return_value = "urn:aevum:audit:x"
    event.event_type = "ingest.accepted"
    event.actor = "test-actor"
    event.sequence = 1
    event.episode_id = None

    bridge.on_event(event)

    spans = exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert attrs.get("gen_ai.system") == "aevum"


def test_bridge_omits_system_when_opted_in(monkeypatch) -> None:
    """bridge.on_event omits gen_ai.system when latest semconv is opted in."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from aevum.otel import AevumOTelBridge

    monkeypatch.setenv("OTEL_SEMCONV_STABILITY_OPT_IN", "gen_ai_latest_experimental")

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    bridge = AevumOTelBridge(service_name="test", tracer_provider=provider)

    event = MagicMock()
    event.audit_id.return_value = "urn:aevum:audit:x"
    event.event_type = "ingest.accepted"
    event.actor = "test-actor"
    event.sequence = 1
    event.episode_id = None

    bridge.on_event(event)

    spans = exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert "gen_ai.system" not in attrs
    assert attrs.get("gen_ai.provider.name") == "aevum"


def test_bridge_emits_agent_name_when_capture_enabled(monkeypatch) -> None:
    """With capture enabled, gen_ai.agent.name is set from event.actor."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from aevum.otel import AevumOTelBridge

    monkeypatch.setenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true")
    monkeypatch.delenv("OTEL_SEMCONV_STABILITY_OPT_IN", raising=False)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    bridge = AevumOTelBridge(service_name="test", tracer_provider=provider)

    event = MagicMock()
    event.audit_id.return_value = "urn:aevum:audit:x"
    event.event_type = "ingest.accepted"
    event.actor = "my-agent"
    event.sequence = 1
    event.episode_id = None

    bridge.on_event(event)

    spans = exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert attrs.get("gen_ai.agent.name") == "my-agent"


def test_bridge_no_agent_name_in_default_mode(monkeypatch) -> None:
    """gen_ai.agent.name is not emitted in default (privacy-preserving) mode."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from aevum.otel import AevumOTelBridge

    monkeypatch.delenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", raising=False)
    monkeypatch.delenv("OTEL_SEMCONV_STABILITY_OPT_IN", raising=False)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    bridge = AevumOTelBridge(service_name="test", tracer_provider=provider)

    event = MagicMock()
    event.audit_id.return_value = "urn:aevum:audit:x"
    event.event_type = "ingest.accepted"
    event.actor = "secret-agent"
    event.sequence = 1
    event.episode_id = None

    bridge.on_event(event)

    spans = exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert "gen_ai.agent.name" not in attrs
