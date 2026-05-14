"""
ingest — RELATE — governed membrane entry. Spec Section 08.3.

Phase 3 barrier order (MANDATORY — do not reorder):
  1. crisis_barrier_check  → raises BarrierError if crisis content detected
  2. provenance check      → Barrier 5: source_id required
  3. consent check         → Barrier 3: active grant required
  4. Cedar ABAC            → action="relate_graph_write"; denies on crisis or ceiling
  5. pySHACL validation    → if TypedFact data provided
  6. named graph write     → pyoxigraph KNOWLEDGE + PROVENANCE graphs
  7. graph store write     → in-memory / backend graph store
  8. ledger append         → append-only audit event
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import BarrierError, check_consent, check_crisis, check_provenance, crisis_barrier_check
from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore
from aevum.core.types import SourceType, TypedFact

logger = logging.getLogger(__name__)

_OTEL_GENAI_KEYS: frozenset[str] = frozenset({
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.system",
    "gen_ai.conversation.id",
    "gen_ai.operation.name",
})

# Named graph URIs (Frozen Invariant 10)
_KNOWLEDGE_GRAPH_URI = "https://aevum.build/graph/knowledge"
_PROVENANCE_GRAPH_URI = "https://aevum.build/graph/provenance"
_AEVUM_ONTOLOGY = "https://aevum.build/ontology#"
_AEVUM_ENTITY = "https://aevum.build/entity/"
_AEVUM_FACT = "https://aevum.build/fact/"


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


def _build_typed_fact(
    subject_id: str,
    data: dict[str, Any],
    provenance: dict[str, Any],
    audit_id: str,
) -> TypedFact | None:
    """
    Try to build a TypedFact from data dict.
    Returns None if data lacks required TypedFact fields (backward compat).
    """
    subject = data.get("subject", subject_id)
    predicate = data.get("predicate", "")
    object_value = data.get("object_value", data.get("value", ""))
    source_type_str = data.get("source_type", "")

    if not predicate or not object_value or not source_type_str:
        return None

    try:
        source_type = SourceType(source_type_str)
    except ValueError:
        return None

    taint_raw = data.get("taint_labels", [])
    taint_labels = tuple(str(t) for t in taint_raw)

    return TypedFact(
        fact_id=f"{_AEVUM_FACT}{_uuid7()}",
        subject=str(subject),
        predicate=str(predicate),
        object_value=str(object_value),
        source=provenance.get("source_id", "unknown"),
        source_type=source_type,
        classification=str(provenance.get("classification", 0)),
        taint_labels=taint_labels,
        ingested_at=datetime.now(UTC),
        provenance_id=audit_id,
    )


def _typed_fact_to_ttl(fact: TypedFact) -> str:
    """Render a TypedFact as Turtle RDF for SHACL validation."""
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    return (
        f'@prefix aevum: <{_AEVUM_ONTOLOGY}> .\n'
        f'@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n'
        f'<{fact.fact_id}> a aevum:TypedFact ;\n'
        f'    aevum:subject "{esc(fact.subject)}"^^xsd:string ;\n'
        f'    aevum:predicate "{esc(fact.predicate)}"^^xsd:string ;\n'
        f'    aevum:objectValue "{esc(fact.object_value)}" ;\n'
        f'    aevum:sourceType "{esc(fact.source_type)}" .\n'
    )


def _write_to_named_graphs(fact: TypedFact, audit_id: str) -> None:
    """
    Write fact to pyoxigraph named graphs (KNOWLEDGE + PROVENANCE).
    No-op if pyoxigraph is not installed — graph store protocol handles storage.
    """
    try:
        from pyoxigraph import Literal, NamedNode, Quad, Store
    except ImportError:
        return

    _XSD_STRING = NamedNode("http://www.w3.org/2001/XMLSchema#string")

    try:
        store = Store()  # in-process ephemeral store for named graph record
        kg = NamedNode(_KNOWLEDGE_GRAPH_URI)
        pg = NamedNode(_PROVENANCE_GRAPH_URI)
        ont = _AEVUM_ONTOLOGY

        fact_node = NamedNode(fact.fact_id)
        rdf_type = NamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
        typed_fact_class = NamedNode(f"{ont}TypedFact")

        store.add(Quad(fact_node, rdf_type, typed_fact_class, kg))
        store.add(Quad(fact_node, NamedNode(f"{ont}subject"), Literal(fact.subject, datatype=_XSD_STRING), kg))
        store.add(Quad(fact_node, NamedNode(f"{ont}predicate"), Literal(fact.predicate, datatype=_XSD_STRING), kg))
        store.add(Quad(fact_node, NamedNode(f"{ont}objectValue"), Literal(fact.object_value, datatype=_XSD_STRING), kg))
        store.add(Quad(fact_node, NamedNode(f"{ont}sourceType"), Literal(str(fact.source_type), datatype=_XSD_STRING), kg))

        # provenance named graph entry
        audit_node = NamedNode(audit_id if audit_id.startswith("http") else f"urn:aevum:{audit_id}")
        store.add(Quad(audit_node, NamedNode(f"{ont}provenanceFor"), fact_node, pg))
        ingested_lit = Literal(fact.ingested_at.isoformat(), datatype=_XSD_STRING)
        store.add(Quad(audit_node, NamedNode(f"{ont}ingestedAt"), ingested_lit, pg))
        store.add(Quad(audit_node, NamedNode(f"{ont}source"), Literal(fact.source, datatype=_XSD_STRING), pg))

        logger.debug("Named graph write: %d quads for fact %s", len(store), fact.fact_id)
    except Exception:  # noqa: BLE001
        logger.debug("Named graph write skipped (pyoxigraph store not configured)", exc_info=True)


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

    # Step 1 — Crisis barrier (MUST be first — Canary 1 verifies this order)
    text_for_crisis = " ".join(str(v) for v in data.values()) + " " + purpose
    try:
        crisis_barrier_check(text_for_crisis)
    except BarrierError as exc:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "ingest"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return OutputEnvelope.crisis(
            audit_id=provisional_id,
            safe_message=str(exc),
            resources=[],
            provenance=ProvenanceRecord(
                source_id="aevum-core", ingest_audit_id=provisional_id,
                chain_of_custody=["aevum-core"], classification=0,
            ),
        )

    # Also use the dict-based crisis check (covers nested values)
    crisis = check_crisis(data, provisional_id)
    if crisis is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "ingest"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return crisis

    # Step 2 — Provenance barrier (Barrier 5)
    prov_err = check_provenance(provenance, provisional_id)
    if prov_err is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 5, "function": "ingest"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return prov_err

    # Step 3 — Consent barrier (Barrier 3)
    consent_err = check_consent(subject_id=subject_id, operation="ingest",
                                grantee_id=actor, consent_ledger=consent_ledger,
                                audit_id=provisional_id)
    if consent_err is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 3, "function": "ingest", "subject_id": subject_id},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return consent_err

    classification = provenance.get("classification", 0)

    # Step 4 — Cedar ABAC: action="relate_graph_write"
    try:
        from aevum.core.cedar_engine import CedarPolicyEngine
        cedar_engine = CedarPolicyEngine.default()
        cedar_context: dict[str, Any] = {
            "has_crisis_content": False,
            "data_classification_level": classification,
            "deployment_ceiling_level": 3,
            "has_active_consent": True,
            "consent_purpose_matches": True,
            "autonomy_level": 1,
        }
        permitted = cedar_engine.is_permitted(
            principal_type="AevumAgent",
            principal_id=actor,
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=cedar_context,
        )
        if not permitted:
            ledger.append(event_type="barrier.triggered",
                          payload={"barrier": 2, "function": "ingest", "reason": "cedar_deny"},
                          actor=actor, episode_id=episode_id, correlation_id=correlation_id)
            return OutputEnvelope.error(
                audit_id=provisional_id,
                error_code="cedar_denied",
                error_detail="Cedar ABAC denied relate_graph_write",
                provenance=ProvenanceRecord(
                    source_id="aevum-core", ingest_audit_id=provisional_id,
                    chain_of_custody=["aevum-core"], classification=0,
                ),
            )
    except Exception:  # noqa: BLE001
        logger.debug("Cedar ABAC check skipped (engine unavailable)", exc_info=True)

    # Step 5 — Build TypedFact and run pySHACL validation (when applicable)
    typed_fact: TypedFact | None = _build_typed_fact(subject_id, data, provenance, provisional_id)
    if typed_fact is not None:
        try:
            from aevum.core.shacl_validator import SHACLValidationError, validate_fact_rdf
            ttl = _typed_fact_to_ttl(typed_fact)
            validate_fact_rdf(ttl)
        except SHACLValidationError:
            raise
        except ImportError:
            logger.debug("pySHACL not available; skipping SHACL validation")

        # Step 6 — Write to pyoxigraph named graphs
        _write_to_named_graphs(typed_fact, provisional_id)

    # Step 7 — Write to in-memory / backend graph store
    graph.store_entity(subject_id, data, classification=classification)

    # Step 8 — Append to episodic ledger
    event_payload: dict[str, Any] = {
        "subject_id": subject_id, "purpose": purpose,
        "source_id": provenance.get("source_id", ""), "classification": classification,
    }
    if typed_fact is not None:
        event_payload["fact_id"] = typed_fact.fact_id
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

    result_data: dict[str, Any] = {"ingested": True, "subject_id": subject_id}
    if typed_fact is not None:
        result_data["typed_fact"] = {
            "fact_id": typed_fact.fact_id,
            "subject": typed_fact.subject,
            "predicate": typed_fact.predicate,
            "object_value": typed_fact.object_value,
            "source_type": str(typed_fact.source_type),
        }

    result = OutputEnvelope.ok(
        audit_id=audit_id,
        data=result_data,
        provenance=prov_record,
    )
    if idempotency_key and idempotency_cache is not None:
        idempotency_cache[idempotency_key] = result
    return result
