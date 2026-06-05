# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
AevumOTelBridge — sigchain events → OTel GenAI spans.

Privacy model:
  Default: emit only audit_id as gen_ai.content.reference.
  Opt-in:  set OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
           to also emit event_type and actor in span attributes.

The bridge registers itself as a ledger observer and emits one OTel span
per AuditEvent. Span duration is always 0 (events are instantaneous writes).

Complication manifest:
  name: "aevum-otel-bridge"
  version: "0.6.0"
  capabilities: ["telemetry.otel"]

Install via:
    engine.install_complication(bridge, auto_approve=True)
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aevum.core.audit.event import AuditEvent
    from opentelemetry.trace import Span

_logger = logging.getLogger("aevum.otel")


def _set_genai_provider(span: Span, provider_name: str) -> None:
    """Emit gen_ai provider attributes with migration compatibility.

    Always emits gen_ai.provider.name (OTel GenAI semconv v1.38+).
    Also emits gen_ai.system for backends not yet on v1.38+ unless
    OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental is set.

    Reference: opentelemetry.io/docs/specs/semconv/gen-ai/
    Migration: traceloop/openllmetry#3515
    """
    opt_in = os.environ.get("OTEL_SEMCONV_STABILITY_OPT_IN", "").lower()
    span.set_attribute("gen_ai.provider.name", provider_name)
    if "gen_ai_latest_experimental" not in opt_in:
        span.set_attribute("gen_ai.system", provider_name)


def _make_span_name(operation: str, model: str) -> str:
    # Span name format: "{operation} {model}" per OTel GenAI semconv
    # https://opentelemetry.io/docs/specs/semconv/gen-ai/
    return f"{operation} {model}"


_MANIFEST: dict[str, Any] = {
    "name": "aevum-otel-bridge",
    "version": "0.6.0",
    "schema_version": "1.0",
    "capabilities": ["telemetry.otel"],
    "description": "Routes Aevum sigchain events to OTel GenAI spans.",
    "author": "Aevum Labs",
    "classification_max": 0,
    "functions": ["ingest", "query", "review", "commit", "replay"],
    "auth": {"public_key": None},
}

# OTel GenAI semantic convention attribute names
_ATTR_AUDIT_ID = "gen_ai.content.reference"
_ATTR_EVENT_TYPE = "aevum.event_type"
_ATTR_ACTOR = "aevum.actor"
_ATTR_SEQUENCE = "aevum.sequence"
_ATTR_EPISODE_ID = "aevum.episode_id"


def _capture_content_enabled() -> bool:
    return (
        os.environ.get(
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", ""
        ).lower()
        in ("true", "1", "yes")
    )


class AevumOTelBridge:
    """
    OpenTelemetry bridge complication.

    Subscribes to ledger events and emits OTel GenAI spans to the configured
    OTLP endpoint (or any registered TracerProvider).

    Args:
        service_name:    OTel service name (default: "aevum").
        tracer_provider: Optional pre-configured TracerProvider. If None,
                         uses the global OTel TracerProvider.
        endpoint:        Optional OTLP endpoint URL. If set, registers an
                         OTLP HTTP exporter (requires aevum-otel[otlp-http]).
                         If None, uses the global provider (e.g. console exporter
                         configured by the host application).
    """

    name: str = "aevum-otel-bridge"

    def __init__(
        self,
        *,
        service_name: str = "aevum",
        tracer_provider: Any | None = None,
        endpoint: str | None = None,
    ) -> None:
        from opentelemetry import trace

        self._service_name = service_name

        if tracer_provider is not None:
            self._tracer_provider = tracer_provider
        elif endpoint is not None:
            self._tracer_provider = self._build_otlp_provider(service_name, endpoint)
        else:
            self._tracer_provider = trace.get_tracer_provider()

        self._tracer = self._tracer_provider.get_tracer(
            "aevum.otel.bridge",
            schema_url="https://opentelemetry.io/schemas/1.28.0",
        )
        self._latency_samples: list[float] = []

    def _build_otlp_provider(self, service_name: str, endpoint: str) -> Any:
        """Build a TracerProvider with OTLP HTTP exporter."""
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError as exc:
            raise ImportError(
                "OTLP HTTP exporter requires: pip install 'aevum-otel[otlp-http]'"
            ) from exc

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        return provider

    def manifest(self) -> dict[str, Any]:
        return _MANIFEST

    def set_event_observer(self, ledger: Any) -> None:
        """Called by Engine.install_complication() to hook into ledger events."""
        if hasattr(ledger, "add_observer"):
            ledger.add_observer(self)
        else:
            _logger.warning(
                "Ledger %r does not support add_observer — "
                "AevumOTelBridge will not emit spans",
                ledger,
            )

    def on_event(self, event: AuditEvent) -> None:
        """
        Called for each AuditEvent appended to the ledger.
        Emits one OTel span per event.
        """
        import time  # noqa: PLC0415

        from opentelemetry.trace import SpanKind, StatusCode

        t0 = time.monotonic()
        capture = _capture_content_enabled()

        try:
            with self._tracer.start_as_current_span(
                f"aevum.{event.event_type}",
                kind=SpanKind.INTERNAL,
            ) as span:
                # Always-safe: audit reference only
                span.set_attribute(_ATTR_AUDIT_ID, event.audit_id())
                span.set_attribute(_ATTR_SEQUENCE, event.sequence)
                _set_genai_provider(span, "aevum")

                if event.episode_id:
                    span.set_attribute(_ATTR_EPISODE_ID, event.episode_id)

                if capture:
                    # Opt-in: richer attributes
                    span.set_attribute(_ATTR_EVENT_TYPE, event.event_type)
                    span.set_attribute(_ATTR_ACTOR, event.actor)
                    if agent_name := getattr(event, "actor", None):
                        span.set_attribute("gen_ai.agent.name", str(agent_name))

                span.set_status(StatusCode.OK)
        except Exception as exc:  # noqa: BLE001
            _logger.error("OTel span emission failed (suppressed): %s", exc)
        finally:
            elapsed_ms = (time.monotonic() - t0) * 1000
            self._latency_samples.append(elapsed_ms)

    def latency_p99_ms(self) -> float | None:
        """Return the p99 latency in ms over all observed events, or None if no data."""
        if not self._latency_samples:
            return None
        sorted_samples = sorted(self._latency_samples)
        idx = int(len(sorted_samples) * 0.99)
        return sorted_samples[min(idx, len(sorted_samples) - 1)]

    def reset_latency_samples(self) -> None:
        self._latency_samples.clear()
