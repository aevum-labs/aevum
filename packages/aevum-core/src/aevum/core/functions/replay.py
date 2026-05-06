"""
replay — faithful reconstruction of past decision. Spec Section 08.7.
Read-only, deterministic, consent-gated.
"""

from __future__ import annotations

from typing import Any

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import check_consent
from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord
from aevum.core.exceptions import ReplayNotFoundError
from aevum.core.functions.ingest import _merge_model_context
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol


def replay(
    *,
    audit_id: str,
    actor: str,
    ledger: AuditLedgerProtocol,
    consent_ledger: ConsentLedgerProtocol,
    scope: list[str] | None = None,
    episode_id: str | None = None,
    correlation_id: str | None = None,
    model_context: dict[str, Any] | None = None,
) -> OutputEnvelope:
    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    try:
        original_event: AuditEvent = ledger.get(audit_id)
    except ReplayNotFoundError:
        return OutputEnvelope.error(
            audit_id=provisional_id,
            error_code="replay_not_found",
            error_detail=f"No ledger entry for audit_id: {audit_id!r}",
            provenance=ProvenanceRecord.kernel(provisional_id),
        )

    subject_id = original_event.payload.get("subject_id")
    if subject_id:
        consent_err = check_consent(subject_id=subject_id, operation="replay",
                                    grantee_id=actor, consent_ledger=consent_ledger,
                                    audit_id=provisional_id)
        if consent_err is not None:
            return consent_err

    replay_payload: dict[str, Any] = {
        "original_audit_id": audit_id,
        "original_event_type": original_event.event_type,
        "replayed_by": actor,
    }
    _merge_model_context(replay_payload, model_context)

    replay_event = ledger.append(
        event_type="replay.complete",
        payload=replay_payload,
        actor=actor, episode_id=episode_id,
        causation_id=audit_id, correlation_id=correlation_id,
    )
    return OutputEnvelope.ok(
        audit_id=replay_event.audit_id(),
        data={"replayed_payload": original_event.payload},
        provenance=ProvenanceRecord(
            source_id="episodic-ledger",
            ingest_audit_id=audit_id,
            chain_of_custody=["episodic-ledger", audit_id],
            classification=0,
        ),
    )
