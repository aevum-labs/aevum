"""
Absolute Barriers — hardcoded, unconditional, non-configurable.
Spec Section 09.3. Canary tests in tests/test_canary.py.
"""

from __future__ import annotations

from typing import Any

from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord

_CRISIS_KEYWORDS: frozenset[str] = frozenset({
    "kill myself", "end my life", "want to die", "commit suicide",
    "hurt someone", "going to hurt", "harm myself",
    "heart attack", "can't breathe", "i can't breathe",
    "overdose", "going to shoot", "going to stab",
})

_CRISIS_SAFE_MESSAGE = (
    "It sounds like you or someone you know may be going through something "
    "very difficult. Please reach out to a crisis service — you don't have to face this alone."
)
_CRISIS_RESOURCES = [
    "988 Suicide & Crisis Lifeline: call or text 988 (US)",
    "Crisis Text Line: text HOME to 741741 (US)",
    "International Association for Suicide Prevention: https://www.iasp.info/resources/Crisis_Centres/",
]


def _text_from_data(data: dict[str, Any]) -> str:
    parts = []
    for v in data.values():
        parts.append(str(v) if not isinstance(v, str) else v)
    return " ".join(parts).lower()


def _kernel_provenance(audit_id: str) -> ProvenanceRecord:
    return ProvenanceRecord(
        source_id="aevum-core", ingest_audit_id=audit_id,
        chain_of_custody=["aevum-core"], classification=0,
    )


def check_crisis(data: dict[str, Any], audit_id: str) -> OutputEnvelope | None:
    """Barrier 1 — CRISIS. Returns crisis envelope or None."""
    if any(kw in _text_from_data(data) for kw in _CRISIS_KEYWORDS):
        return OutputEnvelope.crisis(
            audit_id=audit_id,
            safe_message=_CRISIS_SAFE_MESSAGE,
            resources=_CRISIS_RESOURCES,
            provenance=_kernel_provenance(audit_id),
        )
    return None


def apply_classification_ceiling(
    results: dict[str, Any],
    classifications: dict[str, int],
    actor_clearance: int,
) -> tuple[dict[str, Any], list[str]]:
    """Barrier 2 — CLASSIFICATION CEILING. Redacts above-clearance items."""
    filtered: dict[str, Any] = {}
    redacted: list[str] = []
    for entity_id, entity_data in results.items():
        if classifications.get(entity_id, 0) <= actor_clearance:
            filtered[entity_id] = entity_data
        else:
            redacted.append(entity_id)
    return filtered, redacted


def check_consent(
    *,
    subject_id: str,
    operation: str,
    grantee_id: str,
    consent_ledger: Any,
    audit_id: str,
) -> OutputEnvelope | None:
    """Barrier 3 — CONSENT. Returns error envelope or None."""
    if not consent_ledger.has_consent(
        subject_id=subject_id, operation=operation, grantee_id=grantee_id
    ):
        return OutputEnvelope.error(
            audit_id=audit_id,
            error_code="consent_required",
            error_detail=f"No active consent grant for operation '{operation}' on subject '{subject_id}' by '{grantee_id}'",
            provenance=_kernel_provenance(audit_id),
        )
    return None


# Barrier 4 — AUDIT IMMUTABILITY enforced by InMemoryLedger.__delitem__/__setitem__


def check_provenance(provenance: dict[str, Any], audit_id: str) -> OutputEnvelope | None:
    """Barrier 5 — PROVENANCE. Returns error envelope or None."""
    if not provenance or not provenance.get("source_id"):
        return OutputEnvelope.error(
            audit_id=audit_id,
            error_code="provenance_required",
            error_detail="Provenance record is missing or has no source_id",
            provenance=_kernel_provenance(audit_id),
        )
    return None
