# SPDX-License-Identifier: Apache-2.0
"""Tests for AevumOTelBridge complication."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from aevum.otel import AevumOTelBridge


def _make_bridge() -> tuple[AevumOTelBridge, InMemorySpanExporter]:
    """Create a bridge wired to an in-memory span exporter for testing."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    bridge = AevumOTelBridge(service_name="test-service", tracer_provider=provider)
    return bridge, exporter


def _make_mock_event(
    event_type: str = "ingest.accepted",
    actor: str = "test-agent",
    sequence: int = 1,
    episode_id: str | None = None,
) -> MagicMock:
    event = MagicMock()
    event.audit_id.return_value = "urn:aevum:audit:test-123"
    event.event_type = event_type
    event.actor = actor
    event.sequence = sequence
    event.episode_id = episode_id
    return event


# ── Manifest ──────────────────────────────────────────────────────────────────

class TestManifest:
    def test_manifest_name(self):
        bridge = AevumOTelBridge()
        assert bridge.manifest()["name"] == "aevum-otel-bridge"

    def test_manifest_capabilities(self):
        bridge = AevumOTelBridge()
        assert "telemetry.otel" in bridge.manifest()["capabilities"]

    def test_name_attribute(self):
        bridge = AevumOTelBridge()
        assert bridge.name == "aevum-otel-bridge"


# ── Span emission ─────────────────────────────────────────────────────────────

class TestSpanEmission:
    def test_emits_span_per_event(self):
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event())
        spans = exporter.get_finished_spans()
        assert len(spans) == 1

    def test_span_name_includes_event_type(self):
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event(event_type="session.start"))
        spans = exporter.get_finished_spans()
        assert spans[0].name == "aevum.session.start"

    def test_span_has_audit_id_attribute(self):
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event())
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("gen_ai.content.reference") == "urn:aevum:audit:test-123"

    def test_span_has_sequence_attribute(self):
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event(sequence=42))
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("aevum.sequence") == 42

    def test_no_content_in_default_mode(self, monkeypatch):
        monkeypatch.delenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", raising=False)
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event(actor="secret-agent"))
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        # actor should NOT be emitted in default mode
        assert "aevum.actor" not in attrs
        assert "aevum.event_type" not in attrs

    def test_content_emitted_when_opted_in(self, monkeypatch):
        monkeypatch.setenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true")
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event(event_type="ingest.accepted", actor="my-agent"))
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("aevum.actor") == "my-agent"
        assert attrs.get("aevum.event_type") == "ingest.accepted"

    def test_episode_id_emitted_when_present(self):
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event(episode_id="ep-001"))
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("aevum.episode_id") == "ep-001"

    def test_episode_id_absent_when_none(self):
        bridge, exporter = _make_bridge()
        bridge.on_event(_make_mock_event(episode_id=None))
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert "aevum.episode_id" not in attrs


# ── Observer registration ─────────────────────────────────────────────────────

class TestObserverRegistration:
    def test_set_event_observer_registers_with_ledger(self):
        bridge, _ = _make_bridge()
        mock_ledger = MagicMock()
        bridge.set_event_observer(mock_ledger)
        mock_ledger.add_observer.assert_called_once_with(bridge)

    def test_set_event_observer_warns_when_no_add_observer(self, caplog):
        import logging
        bridge, _ = _make_bridge()
        ledger_without_observer = object()  # no add_observer method
        with caplog.at_level(logging.WARNING, logger="aevum.otel"):
            bridge.set_event_observer(ledger_without_observer)
        assert any("add_observer" in r.message for r in caplog.records)


# ── Error resilience ──────────────────────────────────────────────────────────

class TestErrorResilience:
    def test_on_event_does_not_raise_on_bad_event(self):
        bridge, _ = _make_bridge()
        bad_event = MagicMock()
        bad_event.audit_id.side_effect = RuntimeError("broken")
        # Should not raise
        bridge.on_event(bad_event)


# ── Latency ───────────────────────────────────────────────────────────────────

class TestLatency:
    def test_latency_p99_none_when_no_events(self):
        bridge, _ = _make_bridge()
        assert bridge.latency_p99_ms() is None

    def test_latency_p99_populated_after_events(self):
        bridge, _ = _make_bridge()
        for _ in range(100):
            bridge.on_event(_make_mock_event())
        p99 = bridge.latency_p99_ms()
        assert p99 is not None
        assert p99 >= 0

    def test_latency_reset(self):
        bridge, _ = _make_bridge()
        bridge.on_event(_make_mock_event())
        bridge.reset_latency_samples()
        assert bridge.latency_p99_ms() is None


# ── Engine integration ────────────────────────────────────────────────────────

class TestEngineIntegration:
    def test_bridge_receives_events_from_engine(self, monkeypatch):
        """Install bridge in Engine, verify spans are emitted."""
        monkeypatch.setenv("AEVUM_DEV", "1")
        from aevum.core.engine import Engine
        from aevum.core.consent.models import ConsentGrant

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        bridge = AevumOTelBridge(service_name="eng-test", tracer_provider=provider)

        engine = Engine()
        engine.install_complication(bridge, auto_approve=True)

        engine.ingest(
            data={"note": "otel test"},
            provenance={"source_id": "t", "chain_of_custody": ["t"], "classification": 0},
            purpose="test-otel",
            subject_id="u1",
            actor="a1",
        )

        spans = exporter.get_finished_spans()
        span_names = [s.name for s in spans]
        # ingest.accepted span should be present
        assert any("ingest" in n for n in span_names), f"No ingest span in: {span_names}"

    def test_bridge_p99_latency_under_2ms(self, monkeypatch):
        """
        B-14: OTel latency overhead p99 must be < 2ms.
        Uses in-memory span exporter (zero network overhead) to measure
        pure bridge overhead.
        """
        monkeypatch.setenv("AEVUM_DEV", "1")
        from aevum.core.engine import Engine

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        bridge = AevumOTelBridge(service_name="bench", tracer_provider=provider)

        engine = Engine()
        engine.install_complication(bridge, auto_approve=True)
        bridge.reset_latency_samples()

        for i in range(200):
            engine.ingest(
                data={"n": i},
                provenance={"source_id": "t", "chain_of_custody": ["t"], "classification": 0},
                purpose="bench",
                subject_id=f"u{i}",
                actor="a1",
            )

        p99 = bridge.latency_p99_ms()
        assert p99 is not None
        assert p99 < 2.0, f"p99 latency {p99:.3f}ms exceeds 2ms threshold"
