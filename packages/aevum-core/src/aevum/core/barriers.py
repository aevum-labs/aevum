# SPDX-License-Identifier: Apache-2.0
"""
Unconditional Barriers — hardcoded, unconditional, non-configurable.
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


class BarrierError(Exception):
    """
    Raised when an unconditional barrier fires.
    Not configurable. Not catchable in application code (re-raise not permitted).
    """


def crisis_barrier_check(text: str) -> None:
    """
    Check if text contains crisis content.
    Raises BarrierError if crisis content is detected.
    This runs BEFORE entity recognition, BEFORE graph writes.
    It is not configurable. There is no override.
    """
    text_lower = text.lower()
    for pattern in _CRISIS_KEYWORDS:
        if pattern in text_lower:
            raise BarrierError(
                f"Crisis content detected. Barrier 1 activated. "
                f"Session halted. Pattern: {pattern!r}"
            )


def check_crisis(data: dict[str, Any], audit_id: str) -> OutputEnvelope | None:
    """
    Crisis pattern detection barrier (Barrier 1).

    Screens ingested and queried content for crisis indicators before any
    graph operation. If crisis content is detected, the operation is halted
    and a crisis envelope is returned.

    IMPORTANT CLINICAL LIMITATIONS (see THREAT_MODEL.md — Crisis Detection
    Limitations and Crisis Barrier Evasion Techniques):

    - This is a keyword-matching content screen, not a clinical safety system.
    - It is not validated to any clinical standard (FDA, EU MDR, or similar).
    - It is not a medical device.
    - False negatives (missed crisis content) are possible and expected for:
        * Chunked inputs (phrases split across multiple ingest() calls)
        * Elliptical or clinically coded language
        * Non-English or culturally specific crisis expression
    - False positives (incorrectly flagged content) are possible.
    - It does not replace human clinical judgment.
    - It must not be used as the sole safety control for applications
      serving users in mental-health, crisis, or vulnerable-population
      contexts. Complement with human review and clinical-grade tooling.

    See THREAT_MODEL.md — Crisis Detection Limitations and D-02 (Evasion).
    """
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
