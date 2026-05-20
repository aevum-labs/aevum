# aevum-otel

OpenTelemetry bridge complication for Aevum. Routes sigchain events to OTel GenAI spans.

## Install

```bash
pip install aevum-otel
# With OTLP HTTP exporter:
pip install "aevum-otel[otlp-http]"
# With OTLP gRPC exporter:
pip install "aevum-otel[otlp]"
```

## Usage

```python
from aevum.core import Engine
from aevum.otel import AevumOTelBridge

bridge = AevumOTelBridge(service_name="my-service")
engine = Engine()
engine.install_complication(bridge, auto_approve=True)

# All engine calls (ingest, query, etc.) now emit OTel GenAI spans.
```

## Privacy defaults

By default only `audit_id` is emitted as `gen_ai.content.reference`. No prompt or response content is included.

To opt in to richer attributes:

```bash
export OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
```

## GenAI semantic conventions

For the latest experimental GenAI semconv:

```bash
export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
```

See [OTel GenAI semconv documentation](https://opentelemetry.io/docs/specs/semconv/gen-ai/) for details.

## Tested exporters

- Console exporter (always available via `opentelemetry-sdk`)
- Grafana Tempo (document setup if environment permits — otherwise note as untested)
- Langfuse (document setup if environment permits — otherwise note as untested)

## License

Apache-2.0
