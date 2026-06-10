# SPDX-License-Identifier: Apache-2.0
"""
Unconditional Barriers — the five hardcoded safety checks that fire before every graph
or policy operation in aevum-core.

These are NOT policies. They are NOT Cedar rules. They are NOT configurable by any
complication, operator setting, environment variable, or runtime argument. They cannot
be bypassed, overridden, or toggled off. Even dev mode (AEVUM_DEV=1) does not bypass them.

Contrast with the policy engine (aevum.core.policy): policy decisions are configurable,
can be granted or revoked by Cedar policies, and can be overridden via break-glass paths.
Barriers are absolute. If a barrier fires, the operation is halted regardless of what any
policy engine says. The evaluation order for every RELATE/NAVIGATE/GOVERN/REMEMBER call is:
  barriers first → policy engine → knowledge graph write

The five barriers:
  Barrier 1 — Crisis Detection:       halt on self-harm or dangerous-content keywords
  Barrier 2 — Classification Ceiling: BLOCK the operation if any requested data exceeds clearance
                                      (redaction is a separate opt-in, RECORDED feature — never silent)
  Barrier 3 — Consent:                deny if no active consent grant exists for the triple
  Barrier 4 — Audit Immutability:     enforce I1-APPEND_ONLY on the episodic ledger
  Barrier 5 — Provenance:             deny if source_id is missing from the provenance record

Spec reference: Section 09.3. Canary tests verify these at every release: tests/test_canary.py.
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
    """Raised when an unconditional barrier fires and the operation must halt immediately.

    BarrierError signals a hard invariant violation, not a policy denial. Unlike a policy
    engine returning False (which can be retried with different credentials or break-glass),
    a BarrierError means the operation must not proceed under any circumstances. Application
    code must not catch and suppress this exception — it must propagate to the operator's
    error handler, which maps it to an error OutputEnvelope and logs the barrier activation.
    """


def crisis_barrier_check(text: str) -> None:
    """Barrier 1 — Crisis Detection. Scan raw text and raise BarrierError if a crisis keyword is found.

    This is the low-level string check called by check_crisis(). It runs before entity
    recognition, before Cedar policy evaluation, and before any graph write. The keyword
    list (_CRISIS_KEYWORDS) is hardcoded and cannot be changed at runtime — it is not a
    policy configuration. There is no override and no break-glass path for this barrier.

    See check_crisis() for important clinical limitations (false positives/negatives,
    non-English content, chunked inputs). This is not a clinical safety system.

    Raises:
        BarrierError: If any crisis keyword is found in the lowercased text. The error
            message names the matched pattern and states that the session is halted.
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
    """Barrier 2 helper — OPT-IN RECORDED redaction primitive. NOT the default path.

    The default Barrier 2 behaviour is to BLOCK (see check_classification_ceiling). This
    function exists for a future opt-in, explicitly-RECORDED redaction mode where a caller
    deliberately chooses partial results over a hard block. It must never be wired as a
    silent default. It does not raise; it returns (filtered, redacted) and the caller is
    responsible for emitting an audit event when redacted is non-empty — redaction is never
    silent.

    Args:
        results: Dict of entity_id → entity_data to filter.
        classifications: Dict of entity_id → integer classification level (higher = more sensitive).
        actor_clearance: The requesting actor's integer clearance level.

    Returns:
        Tuple of (filtered_results, redacted_ids). filtered_results contains only items
        whose classification is ≤ actor_clearance; redacted_ids lists what was removed.
    """
    filtered: dict[str, Any] = {}
    redacted: list[str] = []
    for entity_id, entity_data in results.items():
        if classifications.get(entity_id, 0) <= actor_clearance:
            filtered[entity_id] = entity_data
        else:
            redacted.append(entity_id)
    return filtered, redacted


def check_classification_ceiling(
    above_ceiling_ids: list[str],
    audit_id: str,
) -> OutputEnvelope | None:
    """Barrier 2 — Classification Ceiling. BLOCK if any requested subject exceeds clearance.

    Canonical behaviour (June 2026 decision): the classification ceiling BLOCKS the whole
    operation rather than silently redacting above-clearance items. If any requested subject's
    classification exceeds the actor's clearance, the operation is denied with
    error_code="classification_blocked". Partial, redacted results are never returned by
    default — redaction is a separate, opt-in, RECORDED feature (see apply_classification_ceiling),
    never silent.

    Mirrors check_consent: does not raise; returns an error OutputEnvelope on denial so the
    caller can append the barrier.triggered event and surface a structured response. A None
    return means every requested subject is within clearance.

    Args:
        above_ceiling_ids: Requested subjects that EXIST and exceed the actor's clearance.
        audit_id: Included in the returned error envelope for traceability.

    Returns:
        None if above_ceiling_ids is empty; an error OutputEnvelope with
        error_code="classification_blocked" otherwise.
    """
    if above_ceiling_ids:
        return OutputEnvelope.error(
            audit_id=audit_id,
            error_code="classification_blocked",
            error_detail=(
                "Classification ceiling exceeded for subjects: "
                f"{', '.join(sorted(above_ceiling_ids))}. Operation blocked (Barrier 2)."
            ),
            provenance=_kernel_provenance(audit_id),
        )
    return None


def check_consent(
    *,
    subject_id: str,
    operation: str,
    grantee_id: str,
    consent_ledger: Any,
    audit_id: str,
) -> OutputEnvelope | None:
    """Barrier 3 — Consent. Deny the operation if no active consent grant exists.

    Consent is checked before Cedar policy evaluation — it is a legal precondition
    (GDPR Art. 6), not a policy option. An actor may hold every Cedar permission available
    and still be denied here if the data subject has not granted consent for this operation.

    This barrier does not raise; it returns an error OutputEnvelope on denial so the engine
    can log the attempt and surface a structured response. A None return means consent is
    present and the operation may proceed to the policy engine.

    Args:
        subject_id: The data subject whose consent is being checked.
        operation: The operation being requested (e.g., "query", "ingest").
        grantee_id: The principal requesting access.
        consent_ledger: Object implementing has_consent(subject_id, operation, grantee_id).
        audit_id: Included in the returned error envelope for traceability.

    Returns:
        None if consent exists; an error OutputEnvelope with error_code="consent_required"
        if no active grant covers this (subject_id, operation, grantee_id) triple.
    """
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


# Barrier 4 — Audit Immutability: the I1-APPEND_ONLY invariant is enforced structurally
# in the ledger implementation. Any attempt to overwrite or delete an existing audit entry
# raises ImmutableLedgerError (see sigchain.py). This barrier has no function in this module
# because its enforcement is architectural — it is baked into the ledger data structure itself.
# Barrier 4 — AUDIT IMMUTABILITY enforced by InMemoryLedger.__delitem__/__setitem__


def check_provenance(provenance: dict[str, Any], audit_id: str) -> OutputEnvelope | None:
    """Barrier 5 — Provenance. Deny the operation if the provenance record is incomplete.

    Every piece of data ingested through the governed membrane must carry a provenance
    record with a non-empty source_id. An empty or missing source_id means the chain of
    custody cannot be established — the data's origin is unknown, which violates the
    "provenance as precondition" invariant (Spec Section 03.4). Data with unknown origin
    must never reach the knowledge graph.

    This barrier fires before any graph write. It does not raise; it returns an error
    OutputEnvelope so the caller can log and surface a structured denial.

    Args:
        provenance: Dict that must contain a non-empty "source_id" key.
        audit_id: Included in the returned error envelope for traceability.

    Returns:
        None if source_id is present and non-empty; an error OutputEnvelope with
        error_code="provenance_required" if source_id is absent or empty.
    """
    if not provenance or not provenance.get("source_id"):
        return OutputEnvelope.error(
            audit_id=audit_id,
            error_code="provenance_required",
            error_detail="Provenance record is missing or has no source_id",
            provenance=_kernel_provenance(audit_id),
        )
    return None
