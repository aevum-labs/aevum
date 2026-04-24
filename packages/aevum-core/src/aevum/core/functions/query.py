"""
query — NAVIGATE — graph traversal for declared purpose. Spec Section 08.4.
"""

from __future__ import annotations

from typing import Any, Literal

from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import check_consent, check_crisis
from aevum.core.consent.ledger import ConsentLedger
from aevum.core.envelope.models import (
    OutputEnvelope,
    ProvenanceRecord,
    ReasoningTrace,
    SourceHealthSummary,
    UncertaintyAnnotation,
)
from aevum.core.protocols.graph_store import GraphStore


def query(
    *,
    purpose: str,
    subject_ids: list[str],
    actor: str,
    ledger: InMemoryLedger,
    consent_ledger: ConsentLedger,
    graph: GraphStore,
    constraints: dict[str, Any] | None = None,
    classification_max: int = 0,
    episode_id: str | None = None,
    correlation_id: str | None = None,
) -> OutputEnvelope:
    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    crisis = check_crisis({"purpose": purpose}, provisional_id)
    if crisis is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "query"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return crisis

    for subject_id in subject_ids:
        consent_err = check_consent(subject_id=subject_id, operation="query",
                                    grantee_id=actor, consent_ledger=consent_ledger,
                                    audit_id=provisional_id)
        if consent_err is not None:
            ledger.append(event_type="barrier.triggered",
                          payload={"barrier": 3, "function": "query", "subject_id": subject_id},
                          actor=actor, episode_id=episode_id, correlation_id=correlation_id)
            return consent_err

    # Graph read — use classification_max for Barrier 2
    results = graph.query_entities(subject_ids=subject_ids, classification_max=classification_max)

    # Track redacted subjects (those requested but not in results)
    redacted = [s for s in subject_ids if s not in results]

    event = ledger.append(
        event_type="query.complete",
        payload={"subject_ids": subject_ids, "purpose": purpose,
                 "result_count": len(results), "redacted_count": len(redacted)},
        actor=actor, episode_id=episode_id, correlation_id=correlation_id,
    )
    audit_id = event.audit_id()
    status: Literal["ok", "degraded"] = "degraded" if redacted else "ok"
    warnings = [f"Redacted {len(redacted)} entities above clearance level {classification_max}"] if redacted else []

    return OutputEnvelope(
        status=status,
        data={"results": results},
        audit_id=audit_id,
        confidence=0.9 if not redacted else 0.7,
        uncertainty=UncertaintyAnnotation.empty(),
        provenance=ProvenanceRecord.kernel(audit_id),
        review_required=False,
        review_context=None,
        source_health=SourceHealthSummary.no_complications(),
        warnings=warnings,
        schema_version="1.0",
        reasoning_trace=ReasoningTrace.empty(),
    )
