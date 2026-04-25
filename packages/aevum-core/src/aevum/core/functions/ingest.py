"""
ingest — RELATE — governed membrane entry. Spec Section 08.3.
Barrier order: 1 (crisis) → 5 (provenance) → 3 (consent) → graph write → ledger.
"""

from __future__ import annotations

from typing import Any

from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import check_consent, check_crisis, check_provenance
from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore


def ingest(
    *,
    data: dict[str, Any],
    provenance: dict[str, Any],
    purpose: str,
    subject_id: str,
    actor: str,
    ledger: InMemoryLedger,
    consent_ledger: ConsentLedgerProtocol,
    graph: GraphStore,
    idempotency_key: str | None = None,
    idempotency_cache: dict[str, OutputEnvelope] | None = None,
    episode_id: str | None = None,
    correlation_id: str | None = None,
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

    event = ledger.append(
        event_type="ingest.accepted",
        payload={"subject_id": subject_id, "purpose": purpose,
                 "source_id": provenance.get("source_id", ""), "classification": classification},
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
