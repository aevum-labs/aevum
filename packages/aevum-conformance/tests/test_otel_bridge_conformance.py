# SPDX-License-Identifier: Apache-2.0
"""
Layer 4 — AevumOTelBridge conformance tests (Phase B-08 through B-14).

Verifies the privacy contract and complication manifest contract for AevumOTelBridge.
Skipped automatically if opentelemetry-sdk or aevum-otel is not installed.

Privacy contract (B-10):
  - Default: only audit_id emitted as gen_ai.content.reference.
    Event type and actor are NOT included in spans without explicit opt-in.
  - Opt-in: OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
    adds aevum.event_type and aevum.actor to span attributes.

Manifest contract:
  - name: "aevum-otel-bridge"
  - capabilities: ["telemetry.otel"]

Latency contract (B-14):
  - latency_p99_ms() returns None before any event, float after.

Reference: aevum.otel.bridge.AevumOTelBridge
"""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("opentelemetry")
pytest.importorskip("aevum.otel")

from aevum.otel import AevumOTelBridge  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)


def _make_bridge() -> tuple[AevumOTelBridge, InMemorySpanExporter]:
    """Wire a bridge to an in-memory exporter — no OTLP endpoint needed."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return AevumOTelBridge(service_name="conformance-test", tracer_provider=provider), exporter


def _make_event(
    event_type: str = "ingest.accepted",
    actor: str = "test-agent",
    sequence: int = 1,
    episode_id: str | None = None,
) -> Any:
    e = MagicMock()
    e.audit_id.return_value = "urn:aevum:audit:conformance-000"
    e.event_type = event_type
    e.actor = actor
    e.sequence = sequence
    e.episode_id = episode_id
    return e


class TestManifestContract:
    """Complication manifest must declare the correct identity and capability."""

    def test_manifest_name_is_aevum_otel_bridge(self) -> None:
        bridge = AevumOTelBridge()
        assert bridge.manifest()["name"] == "aevum-otel-bridge"

    def test_manifest_capabilities_includes_telemetry_otel(self) -> None:
        bridge = AevumOTelBridge()
        assert "telemetry.otel" in bridge.manifest()["capabilities"]

    def test_bridge_class_name_attribute(self) -> None:
        assert AevumOTelBridge.name == "aevum-otel-bridge"

    def test_manifest_has_schema_version(self) -> None:
        bridge = AevumOTelBridge()
        assert "schema_version" in bridge.manifest()


class TestPrivacyDefaultContract:
    """Default mode must emit only audit_id — no payload content, event_type, or actor."""

    def _env_without_capture(self) -> dict[str, str]:
        return {
            k: v for k, v in os.environ.items()
            if k != "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
        }

    def test_default_span_contains_audit_id(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ, self._env_without_capture(), clear=True):
            bridge.on_event(_make_event())
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert "gen_ai.content.reference" in (spans[0].attributes or {})

    def test_default_span_excludes_event_type(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ, self._env_without_capture(), clear=True):
            bridge.on_event(_make_event(event_type="query.accepted"))
        attrs = dict(exporter.get_finished_spans()[0].attributes or {})
        assert "aevum.event_type" not in attrs

    def test_default_span_excludes_actor(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ, self._env_without_capture(), clear=True):
            bridge.on_event(_make_event(actor="sensitive-agent"))
        attrs = dict(exporter.get_finished_spans()[0].attributes or {})
        assert "aevum.actor" not in attrs

    def test_audit_id_value_matches_event(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ, self._env_without_capture(), clear=True):
            bridge.on_event(_make_event())
        span = exporter.get_finished_spans()[0]
        assert span.attributes["gen_ai.content.reference"] == "urn:aevum:audit:conformance-000"  # type: ignore[index]


class TestPrivacyOptInContract:
    """When OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true, richer attributes appear."""

    def test_optin_enables_event_type_attribute(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ,
                        {"OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "true"}):
            bridge.on_event(_make_event(event_type="ingest.accepted"))
        attrs = dict(exporter.get_finished_spans()[0].attributes or {})
        assert "aevum.event_type" in attrs

    def test_optin_enables_actor_attribute(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ,
                        {"OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "true"}):
            bridge.on_event(_make_event(actor="billing-agent"))
        attrs = dict(exporter.get_finished_spans()[0].attributes or {})
        assert "aevum.actor" in attrs

    def test_optin_via_value_1(self) -> None:
        bridge, exporter = _make_bridge()
        with patch.dict(os.environ,
                        {"OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "1"}):
            bridge.on_event(_make_event())
        attrs = dict(exporter.get_finished_spans()[0].attributes or {})
        assert "aevum.event_type" in attrs


class TestLatencyContract:
    """latency_p99_ms() must return None before any events and a non-negative float after."""

    def test_returns_none_before_any_event(self) -> None:
        bridge, _ = _make_bridge()
        assert bridge.latency_p99_ms() is None

    def test_returns_float_after_one_event(self) -> None:
        bridge, _ = _make_bridge()
        bridge.on_event(_make_event())
        result = bridge.latency_p99_ms()
        assert result is not None
        assert isinstance(result, float)
        assert result >= 0.0

    def test_reset_clears_samples(self) -> None:
        bridge, _ = _make_bridge()
        bridge.on_event(_make_event())
        bridge.reset_latency_samples()
        assert bridge.latency_p99_ms() is None
