# SPDX-License-Identifier: Apache-2.0
"""
query — NAVIGATE — graph traversal for declared purpose. Spec Section 08.4.

Phase 3 additions:
  - Cedar ABAC: action="navigate" with consent context
  - 3-axis relevance decay scoring (distance × complexity × size)
  - ContextBundle assembly with mandatory uncertainty + reasoning_trace
  - agent_prompt generation for direct LLM injection
  - ContextBundle included in OutputEnvelope.data["context_bundle"]

Calls active complications and stores results in the ledger for faithful replay.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime
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
from aevum.core.policy import NullPolicyEngine, PolicyEngine
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore
from aevum.core.types import (
    Completeness,
    ContextBundle,
    ExclusionNote,
    SourceType,
    TypedFact,
    WeightedEdge,
)
from aevum.core.witness import Witness
from aevum.core.witness import capture as capture_witness_fn

if TYPE_CHECKING:
    from aevum.core.complications.circuit_breaker import CircuitBreaker
    from aevum.core.complications.registry import ComplicationRegistry

logger = logging.getLogger(__name__)


def _json_safe(value: Any) -> Any:
    """Round-trip through JSON to ensure serializability."""
    return json.loads(json.dumps(value, default=str))


def compute_edge_score(
    distance: float,
    complexity: float,
    size: float,
    lambda_d: float = 0.3,
) -> float:
    """
    3-axis relevance score combining distance, complexity, and size.
    Returns a float in [0.0, 1.0].

    Axes:
      Distance: exponential decay — closer nodes score higher
      Complexity: inverse — simpler (more focused) nodes score higher
      Size: log-scaled — medium-sized content scores higher than tiny or huge
    """
    d_score = math.exp(-lambda_d * distance)
    c_score = 1.0 / (1.0 + complexity)
    s_score = math.log(size + 1.0) / math.log(10_000.0 + 1.0)
    raw = d_score * c_score * s_score
    return min(1.0, max(0.0, raw))


def _graph_results_to_typed_facts(
    graph_results: dict[str, dict[str, Any]],
    purpose: str,
) -> tuple[tuple[TypedFact, ...], tuple[WeightedEdge, ...]]:
    """Convert graph store results to TypedFacts and WeightedEdges with decay scores."""
    facts: list[TypedFact] = []
    edges: list[WeightedEdge] = []
    now = datetime.now(UTC)

    subject_ids = list(graph_results.keys())
    n_subjects = len(subject_ids)

    for i, (subject_id, entity_data) in enumerate(graph_results.items()):
        distance = float(i + 1)
        complexity = float(max(1, len(entity_data)))
        content = json.dumps(entity_data, default=str)
        size = float(len(content))

        score = compute_edge_score(distance, complexity, size)

        for key, value in entity_data.items():
            fact = TypedFact(
                fact_id=f"urn:aevum:fact:{_uuid7()}",
                subject=subject_id,
                predicate=key,
                object_value=str(value),
                source="graph_store",
                source_type=SourceType.SYSTEM,
                classification="0",
                taint_labels=(),
                ingested_at=now,
                provenance_id=f"urn:aevum:provenance:{subject_id}",
            )
            facts.append(fact)

        if n_subjects > 1 and i < n_subjects - 1:
            next_subject = subject_ids[i + 1]
            edge = WeightedEdge(
                from_id=subject_id,
                to_id=next_subject,
                predicate="co_queried",
                distance=distance,
                complexity=complexity,
                size=size,
                score=score,
            )
            edges.append(edge)

    return tuple(facts), tuple(edges)


def _compute_uncertainty(
    facts: tuple[TypedFact, ...],
    excluded: tuple[ExclusionNote, ...],
) -> float:
    """
    Compute uncertainty from coverage ratio.
    Clamped to [0.05, 0.95] — never claim absolute certainty or total ignorance.
    """
    included = len(facts)
    total_relevant = included + len(excluded)
    coverage = included / total_relevant if total_relevant > 0 else 0.0
    uncertainty = 1.0 - coverage
    return max(0.05, min(0.95, uncertainty))


def _build_agent_prompt_text(
    purpose: str,
    assembled_at: datetime,
    facts: tuple[TypedFact, ...],
    excluded: tuple[ExclusionNote, ...],
    uncertainty: float,
    checkpoint_required: bool,
) -> tuple[str, int]:
    """Build agent prompt text from raw components. Returns (text, token_count)."""
    lines: list[str] = [
        f"## Context for: {purpose}",
        f"Assembled: {assembled_at.isoformat()}",
        "",
        "### Relevant Facts",
    ]

    for fact in facts:
        lines.append(
            f"- [{fact.source_type.upper()}] "
            f"{fact.subject} {fact.predicate} {fact.object_value}"
        )

    if excluded:
        lines.append("")
        lines.append(
            f"*Note: {len(excluded)} fact(s) excluded "
            f"(classification, consent, or relevance).*"
        )

    lines.append("")
    lines.append(
        f"### Epistemic Status\n"
        f"Uncertainty: {uncertainty:.0%}. "
        + (
            "This context is likely incomplete."
            if uncertainty > 0.5
            else "This context is reasonably complete."
        )
    )

    if checkpoint_required:
        lines.append("")
        lines.append(
            "CHECKPOINT REQUIRED: The proposed action requires human "
            "review before proceeding."
        )

    text = "\n".join(lines)
    token_count = len(text) // 4
    return text, token_count


def assemble_agent_prompt(
    bundle: ContextBundle,
    max_tokens: int = 4096,
) -> tuple[str, int]:
    """
    Assemble a structured prompt section from a ContextBundle.
    Returns (prompt_text, token_count).
    Token count is estimated as: len(text) // 4.
    """
    return _build_agent_prompt_text(
        purpose=bundle.purpose,
        assembled_at=bundle.assembled_at,
        facts=bundle.facts,
        excluded=bundle.excluded,
        uncertainty=bundle.uncertainty,
        checkpoint_required=bundle.checkpoint_required,
    )


def _build_context_bundle(
    purpose: str,
    facts: tuple[TypedFact, ...],
    edges: tuple[WeightedEdge, ...],
    excluded: tuple[ExclusionNote, ...],
    audit_id: str,
    subject_ids: list[str],
) -> ContextBundle:
    """Assemble a ContextBundle with mandatory uncertainty and reasoning_trace."""
    uncertainty = _compute_uncertainty(facts, excluded)
    included = len(facts)
    total_relevant = included + len(excluded)
    coverage = included / total_relevant if total_relevant > 0 else 0.0

    completeness: Completeness
    if not excluded:
        completeness = Completeness.COMPLETE
    elif included > 0:
        completeness = Completeness.PARTIAL
    else:
        completeness = Completeness.UNCERTAIN

    reasoning_trace = (
        f"Query: {purpose}",
        f"Subjects: {', '.join(subject_ids)}",
        f"Facts retrieved: {included}",
        f"Facts excluded: {len(excluded)}",
        f"Coverage: {coverage:.0%}",
        "3-axis decay applied: lambda_d=0.3",
        f"BFS traversal over {len(subject_ids)} subject(s)",
    )

    audit_int_id = abs(hash(audit_id)) % (2**31)
    now = datetime.now(UTC)
    consent_ref = f"urn:aevum:consent:{subject_ids[0] if subject_ids else 'unknown'}"

    # Build agent_prompt text before constructing ContextBundle (avoids chicken-and-egg
    # with the agent_prompt non-empty invariant when facts are present)
    agent_prompt, token_count = _build_agent_prompt_text(
        purpose=purpose,
        assembled_at=now,
        facts=facts,
        excluded=excluded,
        uncertainty=uncertainty,
        checkpoint_required=False,
    )

    return ContextBundle(
        facts=facts,
        edges=edges,
        uncertainty=uncertainty,
        reasoning_trace=reasoning_trace,
        completeness=completeness,
        excluded=excluded,
        consent_ref=consent_ref,
        purpose=purpose,
        assembled_at=now,
        audit_id=audit_int_id,
        agent_prompt=agent_prompt,
        agent_prompt_tokens=token_count,
        checkpoint_required=False,
        schema_version="2.0",
    )


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
    capture_witness: bool = True,
    policy_engine: PolicyEngine | None = None,
) -> OutputEnvelope:
    """
    Traverse the knowledge graph for a declared purpose.

    Phase 3: adds Cedar ABAC consent check, 3-axis decay scoring, ContextBundle
    assembly with mandatory uncertainty + reasoning_trace, and agent_prompt.
    """
    from aevum.core.complications import _run_coro

    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    # Barrier 1 — Crisis
    crisis = check_crisis({"purpose": purpose}, provisional_id)
    if crisis is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "query"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return crisis

    # Barrier 3 — Consent for all subjects
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

    # ABAC: action="navigate" with consent context
    _abac_engine: PolicyEngine = policy_engine if policy_engine is not None else NullPolicyEngine()
    abac_context: dict[str, Any] = {
        "has_crisis_content": False,
        "has_active_consent": True,
        "consent_purpose_matches": True,
        "data_classification_level": 0,
        "deployment_ceiling_level": 3,
        "autonomy_level": 1,
    }
    if not _abac_engine.is_permitted(
        principal_type="AevumAgent",
        principal_id=actor,
        action="navigate",
        resource_type="DataGraph",
        resource_id="knowledge",
        context=abac_context,
    ):
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 2, "function": "query", "reason": "policy_deny"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return OutputEnvelope.error(
            audit_id=provisional_id,
            error_code="policy_denied",
            error_detail="Policy engine denied navigate",
            provenance=ProvenanceRecord(
                source_id="aevum-core", ingest_audit_id=provisional_id,
                chain_of_custody=["aevum-core"], classification=0,
            ),
        )

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
            except Exception:  # noqa: BLE001
                if cb:
                    cb.record_failure()
                degraded.append(comp.name)

    # Overall source health
    if unavailable and not available:
        overall = "critical"
    elif degraded or unavailable:
        overall = "degraded"
    else:
        overall = "healthy"

    # Build TypedFacts and WeightedEdges with 3-axis decay scoring
    facts, edges = _graph_results_to_typed_facts(graph_results, purpose)

    # Exclusion notes for redacted subjects
    excluded = tuple(
        ExclusionNote(fact_id=s, reason="classification_ceiling")
        for s in redacted
    )

    # Assemble ContextBundle (uncertainty + reasoning_trace are mandatory)
    context_bundle = _build_context_bundle(
        purpose=purpose,
        facts=facts,
        edges=edges,
        excluded=excluded,
        audit_id=provisional_id,
        subject_ids=subject_ids,
    )

    # Ledger append — include complication results for replay faithfulness
    query_payload: dict[str, Any] = {
        "subject_ids": subject_ids,
        "purpose": purpose,
        "result_count": len(graph_results),
        "redacted_count": len(redacted),
        "complication_results": complication_results,
        "uncertainty": context_bundle.uncertainty,
        "completeness": str(context_bundle.completeness),
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

    witness_obj: Witness | None = None
    if capture_witness:
        witness_obj = capture_witness_fn(
            subject_ids=list(subject_ids),
            results=graph_results,
            ledger=ledger,
        )

    # Serialize ContextBundle for the data payload
    bundle_data: dict[str, Any] = {
        "uncertainty": context_bundle.uncertainty,
        "completeness": str(context_bundle.completeness),
        "reasoning_trace": list(context_bundle.reasoning_trace),
        "agent_prompt": context_bundle.agent_prompt,
        "agent_prompt_tokens": context_bundle.agent_prompt_tokens,
        "facts_count": len(context_bundle.facts),
        "excluded_count": len(context_bundle.excluded),
        "checkpoint_required": context_bundle.checkpoint_required,
        "schema_version": context_bundle.schema_version,
    }

    data_payload: dict[str, Any] = {
        "results": graph_results,
        "complication_results": complication_results,
        "context_bundle": bundle_data,
    }
    if witness_obj is not None:
        data_payload["witness"] = witness_obj.as_dict()

    return OutputEnvelope(
        status=status,  # type: ignore[arg-type]
        data=data_payload,
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
