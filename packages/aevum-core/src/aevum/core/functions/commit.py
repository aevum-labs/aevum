"""
commit — REMEMBER — append to the episodic ledger. Spec Section 08.6.
"""

from __future__ import annotations

from typing import Any

from aevum.core.audit.sigchain import _uuid7
from aevum.core.barriers import check_crisis
from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol

_RESERVED_PREFIXES = (
    "ingest.", "query.", "review.", "commit.",
    "replay.", "barrier.", "policy.", "agent.",
)


def commit(
    *,
    event_type: str,
    payload: dict[str, Any],
    actor: str,
    ledger: AuditLedgerProtocol,
    idempotency_key: str | None = None,
    idempotency_cache: dict[str, OutputEnvelope] | None = None,
    episode_id: str | None = None,
    correlation_id: str | None = None,
) -> OutputEnvelope:
    if idempotency_key and idempotency_cache is not None and idempotency_key in idempotency_cache:
        return idempotency_cache[idempotency_key]

    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    crisis = check_crisis(payload, provisional_id)
    if crisis is not None:
        ledger.append(event_type="barrier.triggered",
                      payload={"barrier": 1, "function": "commit"},
                      actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return crisis

    if any(event_type.startswith(p) for p in _RESERVED_PREFIXES):
        error_event = ledger.append(event_type="commit.rejected",
                                    payload={"reason": "reserved_event_type", "event_type": event_type},
                                    actor=actor, episode_id=episode_id, correlation_id=correlation_id)
        return OutputEnvelope.error(
            audit_id=error_event.audit_id(),
            error_code="reserved_event_type",
            error_detail=f"event_type '{event_type}' uses a kernel-reserved prefix.",
            provenance=ProvenanceRecord.kernel(error_event.audit_id()),
        )

    event = ledger.append(event_type=event_type, payload=payload, actor=actor,
                          episode_id=episode_id, correlation_id=correlation_id)
    audit_id = event.audit_id()
    result = OutputEnvelope.ok(
        audit_id=audit_id,
        data={"committed": True, "event_type": event_type},
        provenance=ProvenanceRecord.kernel(audit_id),
    )
    if idempotency_key and idempotency_cache is not None:
        idempotency_cache[idempotency_key] = result
    return result
