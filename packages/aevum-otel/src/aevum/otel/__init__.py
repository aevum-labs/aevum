# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
aevum-otel — OpenTelemetry bridge complication for Aevum.

Routes sigchain events to OpenTelemetry GenAI spans, publishing to any
OTLP-compatible backend (Grafana Tempo, Langfuse, Jaeger, etc.).

Privacy defaults:
  - Only audit_id is emitted (as gen_ai.content.reference).
  - No prompt, response, or payload content is emitted by default.
  - Set OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true to opt in.

GenAI semantic conventions:
  - Set OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental for latest.

Usage:
    from aevum.core import Engine
    from aevum.otel import AevumOTelBridge

    bridge = AevumOTelBridge(service_name="my-service")
    engine = Engine()
    engine.install_complication(bridge, auto_approve=True)

    # Events from engine.ingest(), engine.query(), etc. will now appear
    # as OTel spans in your configured OTLP backend.
"""

from aevum.otel.bridge import AevumOTelBridge
from aevum.otel.foqa_bridge import FOQABridge
from aevum.otel.gatekeeper import GatekeeperFilter

__version__ = "0.8.0"
__all__ = ["AevumOTelBridge", "FOQABridge", "GatekeeperFilter"]
