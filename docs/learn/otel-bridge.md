---
description: "Route Aevum sigchain events to your OTel backend using AevumOTelBridge."
---

# AevumOTelBridge

`AevumOTelBridge` is an Aevum complication that subscribes to ledger events
and emits one OpenTelemetry GenAI span per event, routing sigchain activity
to your OTel backend.

---

## Install

```bash
pip install aevum-otel
```

For OTLP HTTP export:

```bash
pip install "aevum-otel[otlp-http]"
```

---

## What it does

Every time an event is appended to the Aevum episodic ledger — an ingest,
query, commit, review, or replay — the bridge emits an OTel span to your
configured TracerProvider. Span names follow the pattern `aevum.<event_type>`.

The bridge installs as a complication via `engine.install_complication()`:

```python
from aevum.core import Engine
from aevum.otel.bridge import AevumOTelBridge

engine = Engine()
bridge = AevumOTelBridge(service_name="my-service")
engine.install_complication(bridge, auto_approve=True)
```

After installation, every ledger event automatically produces an OTel span.

---

## Privacy model

By default, the bridge emits only the `audit_id` as the span attribute
`gen_ai.content.reference`. No content, prompts, completions, or actor
names are included without explicit opt-in.

This default is mandated by standing rule S-14 and must not be changed.

| Attribute | Default | Opt-in |
|---|---|---|
| `gen_ai.content.reference` (audit_id) | ✓ always | — |
| `aevum.sequence` | ✓ always | — |
| `aevum.episode_id` | ✓ if present | — |
| `aevum.event_type` | — | requires opt-in |
| `aevum.actor` | — | requires opt-in |

---

## Opt-in content capture

Set `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true` to also emit
`event_type` and `actor` as span attributes:

```bash
export OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
```

These attributes are identifiers, not raw content. Raw payload data is never
emitted through the bridge.

---

## OTLP configuration

Point the bridge at your OTLP endpoint:

```python
bridge = AevumOTelBridge(
    service_name="my-service",
    endpoint="http://localhost:4318/v1/traces",
)
```

Or pass a pre-configured TracerProvider:

```python
from opentelemetry.sdk.trace import TracerProvider

provider = TracerProvider(...)
bridge = AevumOTelBridge(tracer_provider=provider)
```

If neither `endpoint` nor `tracer_provider` is provided, the bridge uses the
global OTel TracerProvider (e.g. one configured by your host application via
`opentelemetry-instrument`).

---

## OTel semantic convention opt-in

Set `OTEL_SEMCONV_STABILITY_OPT_IN` to control which semantic convention
generation the OTel SDK uses:

```bash
export OTEL_SEMCONV_STABILITY_OPT_IN=genai
```

The bridge targets the GenAI semantic conventions schema
`https://opentelemetry.io/schemas/1.28.0`.

---

## Latency overhead

The bridge adds less than 0.5 ms p99 latency per event, measured in
Phase B conformance tests (`test_otel_bridge_conformance.py`, 14 tests).
Call `bridge.latency_p99_ms()` to inspect the observed p99 over the
lifetime of the bridge instance.

---

## Backend setup

### Grafana Tempo

Grafana Tempo accepts OTLP traces natively:

```python
bridge = AevumOTelBridge(
    service_name="my-service",
    endpoint="http://<tempo-host>:4318/v1/traces",
)
```

!!! note "Untested against a live Tempo instance"
    The OTLP HTTP export path is verified in CI against a mock collector.
    Grafana Tempo setup instructions above should work but have not been
    validated end-to-end against a running Tempo deployment.

### Langfuse

Langfuse supports OTLP ingestion via its OpenTelemetry endpoint:

```python
bridge = AevumOTelBridge(
    service_name="my-service",
    endpoint="https://cloud.langfuse.com/api/public/otel/v1/traces",
)
```

Set your Langfuse credentials as environment variables per Langfuse's
documentation.

!!! note "Untested against Langfuse"
    The OTLP path should work with Langfuse's OTel endpoint, but attribute
    mapping may differ from Langfuse's native SDK. Not yet verified end-to-end.

---

## Next steps

- [MCP traceparent guide](/learn/guides/mcp/) — traceparent for MCP tool calls
- [Anthropic adapter guide](/learn/guides/anthropic/) — traceparent for direct API calls
- [Architecture](/learn/architecture/) — how the episodic ledger works
