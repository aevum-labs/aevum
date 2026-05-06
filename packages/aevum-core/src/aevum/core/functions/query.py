"""
query — NAVIGATE — graph traversal for declared purpose. Spec Section 08.4.
Calls active complications and stores results in the ledger for faithful replay.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import check_consent, check_crisis
from aevum.core.envelope.models import (
    OutputEnvelope,
    ProvenanceRecord,
    ReasoningTrace,
    SourceHealthSummary,
    UncertaintyAnnotation,
)
from aevum.core.functions.ingest import _merge_model_context
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore

if TYPE_CHECKING:
    from aevum.core.complications.circuit_breaker import CircuitBreaker
    from aevum.core.complications.registry import ComplicationRegistry

logger = logging.getLogger(__name__)


def _json_safe(value: Any) -> Any:
    """Round-trip through JSON to ensure serializability."""
    return json.loads(json.dumps(value, default=str))


def query(
    *,
    purpose: str,
    subject_ids: list[str],
    actor: str,
    ledger: AuditLedgerProtocol,
    consent_ledger: ConsentLedgerProtocol,
    graph: GraphStore,
    constraints: dict[str, Any] | None = None,
    classification_max: int = 0,
    complication_registry: ComplicationRegistry | None = None,
    circuit_breakers: dict[str, CircuitBreaker] | None = None,
    episode_id: str | None = None,
    correlation_id: str | None = None,
    model_context: dict[str, Any] | None = None,
) -> OutputEnvelope:
    """
    Traverse the knowledge graph for a declared purpose.

    Calls all ACTIVE complications in registry order, accumulates their results,
    and appends a single ledger entry containing both graph and complication data
    for deterministic replay.
    """
    from aevum.core.complications import _run_coro

    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    # Barrier 1
    crisis = check_crisis({"purpose": purpose}, provisional_id)
    if crisis is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "query"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return crisis

    # Barrier 3: consent for all subjects
    for subject_id in subject_ids:
        consent_err = check_consent(
            subject_id=subject_id, operation="query", grantee_id=actor,
            consent_ledger=consent_ledger, audit_id=provisional_id,
        )
        if consent_err is not None:
            ledger.append(event_type="barrier.triggered",
                          payload={"barrier": 3, "function": "query", "subject_id": subject_id},
                          actor=actor, episode_id=episode_id, correlation_id=correlation_id)
            return consent_err

    # Graph read (Barrier 2 enforced by GraphStore)
    graph_results = graph.query_entities(
        subject_ids=subject_ids, classification_max=classification_max
    )
    redacted = [s for s in subject_ids if s not in graph_results]

    complication_results: dict[str, Any] = {}
    available: list[str] = []
    degraded: list[str] = []
    unavailable: list[str] = []

    if complication_registry is not None:
        # Build context for complications
        ctx_data = {
            "subject_ids": subject_ids,
            "purpose": purpose,
            "actor": actor,
            "classification_max": classification_max,
        }

        for comp in complication_registry.active_complications():
            cb = (circuit_breakers or {}).get(comp.name)
            if cb and not cb.allow_request():
                unavailable.append(comp.name)
                continue

            try:
                result = _run_coro(comp.run(ctx_data, graph_results))
                result_safe = _json_safe(result)
                complication_results[comp.name] = result_safe
                available.append(comp.name)
                if cb:
                    cb.record_success()
            except Exception:
                if cb:
                    cb.record_failure()
                degraded.append(comp.name)

    # Determine overall source health
    if unavailable and not available:
        overall = "critical"
    elif degraded or unavailable:
        overall = "degraded"
    else:
        overall = "healthy"

    # Append to ledger — include complication results for replay faithfulness
    query_payload: dict[str, Any] = {
        "subject_ids": subject_ids,
        "purpose": purpose,
        "result_count": len(graph_results),
        "redacted_count": len(redacted),
        "complication_results": complication_results,  # stored for replay
    }
    _merge_model_context(query_payload, model_context)

    event = ledger.append(
        event_type="query.complete",
        payload=query_payload,
        actor=actor, episode_id=episode_id, correlation_id=correlation_id,
    )
    audit_id = event.audit_id()

    status = "degraded" if (redacted or degraded or unavailable) else "ok"
    warnings = []
    if redacted:
        warnings.append(f"Redacted {len(redacted)} entities above clearance {classification_max}")
    if degraded:
        warnings.append(f"Complications degraded: {degraded}")
    if unavailable:
        warnings.append(f"Complications unavailable: {unavailable}")

    return OutputEnvelope(
        status=status,  # type: ignore[arg-type]
        data={"results": graph_results, "complication_results": complication_results},
        audit_id=audit_id,
        confidence=0.9 if status == "ok" else 0.7,
        uncertainty=UncertaintyAnnotation.empty(),
        provenance=ProvenanceRecord.kernel(audit_id),
        review_required=False,
        review_context=None,
        source_health=SourceHealthSummary(
            available=available,
            degraded=degraded,
            unavailable=unavailable,
            overall=overall,  # type: ignore[arg-type]
        ),
        warnings=warnings,
        schema_version="1.0",
        reasoning_trace=ReasoningTrace.empty(),
    )
