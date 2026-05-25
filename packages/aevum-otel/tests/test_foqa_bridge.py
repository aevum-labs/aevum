# SPDX-License-Identifier: Apache-2.0
"""Tests for FOQABridge — OTel aggregate FOQA metrics emission."""

from __future__ import annotations

import secrets

import pytest
from aevum.core.exceedance import EXCEEDANCE_CATALOGUE, ExceedanceEvent
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from aevum.otel.foqa_bridge import FOQABridge
from aevum.otel.gatekeeper import GatekeeperFilter

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_provider() -> tuple[MeterProvider, InMemoryMetricReader]:
    """Create a fresh MeterProvider with an in-memory reader."""
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    return provider, reader


@pytest.fixture()
def gatekeeper():
    key = secrets.token_bytes(32)
    return GatekeeperFilter(gatekeeper_key=key)


@pytest.fixture()
def provider_and_reader():
    return _make_provider()


@pytest.fixture()
def bridge(gatekeeper, provider_and_reader):
    provider, _ = provider_and_reader
    return FOQABridge(gatekeeper=gatekeeper, meter_provider=provider)


@pytest.fixture()
def reader(provider_and_reader):
    _, reader = provider_and_reader
    return reader


def _event(exceedance_id: str = "EX-03", **kwargs) -> ExceedanceEvent:
    cat = EXCEEDANCE_CATALOGUE[exceedance_id]
    defaults = dict(
        exceedance_id=exceedance_id,
        exceedance_name=cat["name"],
        aviation_analogy=cat["aviation"],
        session_id="sess-real-001",
        agent_id="agent-real-abc",
        detected_at="2026-05-25T00:00:00+00:00",
        receipt_hash="e" * 64,
        severity=cat["severity"],
        details={},
    )
    defaults.update(kwargs)
    return ExceedanceEvent(**defaults)


def _collect_metric(reader: InMemoryMetricReader, name: str) -> list[dict]:
    """Extract data points for a metric by name from the reader."""
    data = reader.get_metrics_data()
    if data is None:
        return []
    results = []
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name == name:
                    for dp in metric.data.data_points:
                        results.append({
                            "value": dp.value,
                            "attributes": dict(dp.attributes or {}),
                        })
    return results


# ── FOQABridge construction ───────────────────────────────────────────────────

class TestFOQABridgeConstruction:
    def test_requires_gatekeeper(self):
        with pytest.raises(TypeError):
            FOQABridge()  # type: ignore[call-arg]

    def test_accepts_custom_meter_name(self, gatekeeper):
        provider, _ = _make_provider()
        bridge = FOQABridge(
            gatekeeper=gatekeeper,
            meter_name="custom.foqa",
            meter_version="1.0.0",
            meter_provider=provider,
        )
        assert bridge is not None

    def test_uses_global_provider_when_none_given(self, gatekeeper):
        """When meter_provider=None, falls back to global OTel provider."""
        bridge = FOQABridge(gatekeeper=gatekeeper)
        assert bridge is not None


# ── record() — exceedance counter ────────────────────────────────────────────

class TestFOQABridgeRecord:
    def test_record_increments_exceedance_counter(self, bridge, reader):
        bridge.record(_event("EX-03"))
        points = _collect_metric(reader, "aevum.exceedance.count")
        assert len(points) >= 1
        assert points[0]["value"] == 1

    def test_record_uses_exceedance_id_attribute(self, bridge, reader):
        bridge.record(_event("EX-11"))
        points = _collect_metric(reader, "aevum.exceedance.count")
        assert any(p["attributes"].get("exceedance_id") == "EX-11" for p in points)

    def test_record_uses_severity_attribute(self, bridge, reader):
        bridge.record(_event("EX-13"))  # CRITICAL
        points = _collect_metric(reader, "aevum.exceedance.count")
        assert any(p["attributes"].get("severity") == "CRITICAL" for p in points)

    def test_record_does_not_emit_session_id(self, bridge, reader):
        bridge.record(_event("EX-03", session_id="real-session-id"))
        points = _collect_metric(reader, "aevum.exceedance.count")
        for p in points:
            assert "session_id" not in p["attributes"]
            assert "real-session-id" not in str(p["attributes"])

    def test_record_does_not_emit_agent_id(self, bridge, reader):
        bridge.record(_event("EX-03", agent_id="real-agent-xyz"))
        points = _collect_metric(reader, "aevum.exceedance.count")
        for p in points:
            assert "agent_id" not in p["attributes"]
            assert "real-agent-xyz" not in str(p["attributes"])

    def test_record_does_not_emit_receipt_hash(self, bridge, reader):
        receipt_hash = "f" * 64
        bridge.record(_event("EX-03", receipt_hash=receipt_hash))
        points = _collect_metric(reader, "aevum.exceedance.count")
        for p in points:
            assert receipt_hash not in str(p["attributes"])

    def test_record_multiple_events_accumulate(self, bridge, reader):
        for exc_id in ["EX-01", "EX-03", "EX-11", "EX-13"]:
            bridge.record(_event(exc_id))
        points = _collect_metric(reader, "aevum.exceedance.count")
        total = sum(p["value"] for p in points)
        assert total == 4

    def test_record_de_identifies_before_emit(self, bridge, reader):
        """De-identification must happen before any metric data is written."""
        bridge.record(_event("EX-03", session_id="sensitive-session"))
        points = _collect_metric(reader, "aevum.exceedance.count")
        for p in points:
            assert "sensitive-session" not in str(p)


# ── record_session_start() ────────────────────────────────────────────────────

class TestFOQABridgeSessionStart:
    def test_record_session_start_increments_counter(self, bridge, reader):
        bridge.record_session_start()
        points = _collect_metric(reader, "aevum.session.count")
        assert len(points) >= 1
        assert points[0]["value"] == 1

    def test_record_session_start_accumulates(self, bridge, reader):
        bridge.record_session_start()
        bridge.record_session_start()
        bridge.record_session_start()
        points = _collect_metric(reader, "aevum.session.count")
        total = sum(p["value"] for p in points)
        assert total == 3


# ── Metric name verification ───────────────────────────────────────────────────

class TestFOQABridgeMetricNames:
    def test_exceedance_counter_metric_name(self, bridge, reader):
        bridge.record(_event("EX-05"))
        data = reader.get_metrics_data()
        names = []
        if data:
            for rm in data.resource_metrics:
                for sm in rm.scope_metrics:
                    for m in sm.metrics:
                        names.append(m.name)
        assert "aevum.exceedance.count" in names

    def test_session_counter_metric_name(self, bridge, reader):
        bridge.record_session_start()
        data = reader.get_metrics_data()
        names = []
        if data:
            for rm in data.resource_metrics:
                for sm in rm.scope_metrics:
                    for m in sm.metrics:
                        names.append(m.name)
        assert "aevum.session.count" in names
