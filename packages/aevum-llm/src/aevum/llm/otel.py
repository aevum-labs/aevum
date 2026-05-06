"""
aevum.llm.otel — OpenTelemetry GenAI semantic convention mapper.

Converts AuditEvent fields to OTel GenAI span attributes per:
https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/

Privacy: raw prompts and responses are NEVER emitted.
         audit_id is the external-storage reference to content.
         Only hashes and metadata are included.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aevum.core.audit.event import AuditEvent

# OTel GenAI span attribute keys (stable as of OTel GenAI SIG, 2026)
_OTEL_PAYLOAD_KEYS: frozenset[str] = frozenset({
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.system",
    "gen_ai.operation.name",
    "gen_ai.conversation.id",
})

# Hash fields stored in payload by LlmComplication
_HASH_PAYLOAD_KEYS: frozenset[str] = frozenset({
    "prompt_hash",
    "response_hash",
    "model_id",
})

OtelAttributes = dict[str, str | int | float | bool]


def to_otel_attributes(event: AuditEvent) -> OtelAttributes:
    """
    Convert an AuditEvent to OTel GenAI semantic convention attributes.

    Suitable for use as span attributes in an OpenTelemetry trace.
    Raw content is never included — only cryptographic hashes and
    the audit_id (which serves as the external-storage reference).

    Args:
        event: An AuditEvent from the Aevum episodic ledger.

    Returns:
        Dict of span attribute key → value. All values are str/int/float/bool.
    """
    attrs: OtelAttributes = {
        # Aevum-specific attributes (namespaced to avoid collision)
        "aevum.audit_id": event.audit_id(),
        "aevum.episode_id": event.episode_id,
        "aevum.sequence": event.sequence,
        "aevum.actor": event.actor,
        "aevum.event_type": event.event_type,
        "aevum.schema_version": event.schema_version,
        # External storage reference: the audit_id IS the content reference
        # (OTel GenAI "reference to external storage" mode)
        "gen_ai.content.reference": event.audit_id(),
    }

    # OTel GenAI model/provider attributes from payload (if present)
    for key in _OTEL_PAYLOAD_KEYS:
        val = event.payload.get(key)
        if val is not None and isinstance(val, (str, int, float, bool)):
            attrs[key] = val

    # Hash references — never raw content
    for key in _HASH_PAYLOAD_KEYS:
        val = event.payload.get(key)
        if val is not None and isinstance(val, str):
            attrs[f"aevum.gen_ai.{key}"] = val

    # W3C trace context (pass-through if present)
    if event.trace_id:
        attrs["trace_id"] = event.trace_id
    if event.span_id:
        attrs["span_id"] = event.span_id

    # Causal linkage
    if event.causation_id:
        attrs["aevum.causation_id"] = event.causation_id
    if event.correlation_id:
        attrs["aevum.correlation_id"] = event.correlation_id

    return attrs
