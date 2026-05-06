"""
ingest — RELATE — governed membrane entry. Spec Section 08.3.
Barrier order: 1 (crisis) → 5 (provenance) → 3 (consent) → graph write → ledger.
"""

from __future__ import annotations

import logging
from typing import Any

from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import check_consent, check_crisis, check_provenance
from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore

logger = logging.getLogger(__name__)

_OTEL_GENAI_KEYS: frozenset[str] = frozenset({
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.system",
    "gen_ai.conversation.id",
    "gen_ai.operation.name",
})


def _merge_model_context(payload: dict[str, Any], model_context: dict[str, Any] | None) -> None:
    """Merge allowed OTel GenAI keys from model_context into payload in-place."""
    if not model_context:
        return
    for key in _OTEL_GENAI_KEYS:
        if key in model_context:
            val = model_context[key]
            if isinstance(val, (str, int, float, bool)):
                payload[key] = val
            else:
                logger.debug("model_context key %r has unsupported type %s — ignored", key, type(val))
    for key in model_context:
        if key not in _OTEL_GENAI_KEYS:
            logger.debug("model_context key %r is not an allowed OTel GenAI key — ignored", key)


def ingest(
    *,
    data: dict[str, Any],
    provenance: dict[str, Any],
    purpose: str,
    subject_id: str,
    actor: str,
    ledger: AuditLedgerProtocol,
    consent_ledger: ConsentLedgerProtocol,
    graph: GraphStore,
    idempotency_key: str | None = None,
    idempotency_cache: dict[str, OutputEnvelope] | None = None,
    episode_id: str | None = None,
    correlation_id: str | None = None,
    model_context: dict[str, Any] | None = None,
) -> OutputEnvelope:
    if idempotency_key and idempotency_cache is not None and idempotency_key in idempotency_cache:
        return idempotency_cache[idempotency_key]

    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    crisis = check_crisis(data, provisional_id)
    if crisis is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "ingest"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return crisis

    prov_err = check_provenance(provenance, provisional_id)
    if prov_err is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 5, "function": "ingest"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return prov_err

    consent_err = check_consent(subject_id=subject_id, operation="ingest",
                                grantee_id=actor, consent_ledger=consent_ledger,
                                audit_id=provisional_id)
    if consent_err is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 3, "function": "ingest", "subject_id": subject_id},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return consent_err

    classification = provenance.get("classification", 0)
    graph.store_entity(subject_id, data, classification=classification)

    event_payload: dict[str, Any] = {
        "subject_id": subject_id, "purpose": purpose,
        "source_id": provenance.get("source_id", ""), "classification": classification,
    }
    _merge_model_context(event_payload, model_context)

    event = ledger.append(
        event_type="ingest.accepted",
        payload=event_payload,
        actor=actor, episode_id=episode_id, correlation_id=correlation_id,
    )
    audit_id = event.audit_id()
    prov_record = ProvenanceRecord(
        source_id=provenance.get("source_id", ""),
        ingest_audit_id=audit_id,
        chain_of_custody=provenance.get("chain_of_custody", [provenance.get("source_id", "")]),
        classification=classification,
        model_id=provenance.get("model_id"),
    )
    result = OutputEnvelope.ok(
        audit_id=audit_id,
        data={"ingested": True, "subject_id": subject_id},
        provenance=prov_record,
    )
    if idempotency_key and idempotency_cache is not None:
        idempotency_cache[idempotency_key] = result
    return result
