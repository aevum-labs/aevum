"""
review — GOVERN — human decision gate. Spec Section 08.5.
Veto-as-default: silence = veto if deadline elapsed.
"""

from __future__ import annotations

import threading
from datetime import UTC
from typing import Any

from aevum.core.audit.sigchain import _uuid7
from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord, ReviewContext
from aevum.core.exceptions import ReviewAlreadyResolvedError, ReviewNotFoundError
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol


class ReviewStore:
    """In-memory pending reviews. Thread-safe."""

    def __init__(self) -> None:
        self._pending: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, *, proposed_action: str, reason: str, actor: str,
               autonomy_level: int = 1, risk_assessment: str = "",
               deadline_iso: str | None = None) -> str:
        provisional_id = f"urn:aevum:audit:{_uuid7()}"
        with self._lock:
            self._pending[provisional_id] = {
                "proposed_action": proposed_action, "reason": reason,
                "actor": actor, "autonomy_level": autonomy_level,
                "risk_assessment": risk_assessment, "deadline": deadline_iso,
                "status": "pending",
            }
        return provisional_id

    def get(self, audit_id: str) -> dict[str, Any]:
        with self._lock:
            entry = self._pending.get(audit_id)
            if entry is None:
                raise ReviewNotFoundError(f"No pending review for {audit_id!r}")
            return dict(entry)

    def resolve(self, audit_id: str, resolution: str) -> None:
        with self._lock:
            entry = self._pending.get(audit_id)
            if entry is None:
                raise ReviewNotFoundError(f"No pending review for {audit_id!r}")
            if entry["status"] != "pending":
                raise ReviewAlreadyResolvedError(
                    f"Review {audit_id!r} already resolved as {entry['status']!r}"
                )
            entry["status"] = resolution


def review(
    *,
    audit_id: str,
    action: str | None = None,
    actor: str,
    ledger: AuditLedgerProtocol,
    review_store: ReviewStore,
    episode_id: str | None = None,
    correlation_id: str | None = None,
) -> OutputEnvelope:
    from datetime import datetime
    provisional_id = f"urn:aevum:audit:{_uuid7()}"

    try:
        entry = review_store.get(audit_id)
    except ReviewNotFoundError:
        return OutputEnvelope.error(
            audit_id=provisional_id, error_code="review_not_found",
            error_detail=f"No pending review for {audit_id!r}",
            provenance=ProvenanceRecord.kernel(provisional_id),
        )

    # Veto-as-default: check deadline on poll
    if action is None and entry.get("deadline"):
        try:
            deadline = datetime.fromisoformat(entry["deadline"].replace("Z", "+00:00"))
            if datetime.now(UTC) > deadline:
                try:
                    review_store.resolve(audit_id, "vetoed_by_timeout")
                    veto_event = ledger.append(
                        event_type="review.vetoed",
                        payload={"original_audit_id": audit_id, "reason": "veto_as_default_deadline_elapsed"},
                        actor="aevum-core", episode_id=episode_id,
                        causation_id=audit_id, correlation_id=correlation_id,
                    )
                    return OutputEnvelope.error(
                        audit_id=veto_event.audit_id(), error_code="review_vetoed",
                        error_detail="Veto-as-default: deadline elapsed with no human response",
                        provenance=ProvenanceRecord.kernel(veto_event.audit_id()),
                    )
                except ReviewAlreadyResolvedError:
                    pass
        except ValueError:
            pass

    if action is None:
        if entry["status"] == "pending":
            rc = ReviewContext(
                proposed_action=entry["proposed_action"], reason=entry["reason"],
                autonomy_level=entry["autonomy_level"], risk_assessment=entry["risk_assessment"],
            )
            return OutputEnvelope.pending_review(
                audit_id=audit_id, review_context=rc,
                provenance=ProvenanceRecord.kernel(audit_id),
            )
        return OutputEnvelope.ok(
            audit_id=audit_id, data={"resolution": entry["status"]},
            provenance=ProvenanceRecord.kernel(audit_id),
        )

    if action == "approve":
        try:
            review_store.resolve(audit_id, "approved")
        except ReviewAlreadyResolvedError as e:
            return OutputEnvelope.error(
                audit_id=provisional_id, error_code="review_already_resolved",
                error_detail=str(e), provenance=ProvenanceRecord.kernel(provisional_id),
            )
        ev = ledger.append(event_type="review.approved",
                           payload={"original_audit_id": audit_id, "approved_by": actor},
                           actor=actor, episode_id=episode_id,
                           causation_id=audit_id, correlation_id=correlation_id)
        return OutputEnvelope.ok(audit_id=ev.audit_id(), data={"approved": True},
                                 provenance=ProvenanceRecord.kernel(ev.audit_id()))

    if action == "veto":
        try:
            review_store.resolve(audit_id, "vetoed")
        except ReviewAlreadyResolvedError as e:
            return OutputEnvelope.error(
                audit_id=provisional_id, error_code="review_already_resolved",
                error_detail=str(e), provenance=ProvenanceRecord.kernel(provisional_id),
            )
        ev = ledger.append(event_type="review.vetoed",
                           payload={"original_audit_id": audit_id, "vetoed_by": actor},
                           actor=actor, episode_id=episode_id,
                           causation_id=audit_id, correlation_id=correlation_id)
        return OutputEnvelope.error(audit_id=ev.audit_id(), error_code="review_vetoed",
                                    error_detail="Human veto recorded",
                                    provenance=ProvenanceRecord.kernel(ev.audit_id()))

    return OutputEnvelope.error(
        audit_id=provisional_id, error_code="invalid_action",
        error_detail=f"Unknown review action: {action!r}. Use 'approve', 'veto', or None.",
        provenance=ProvenanceRecord.kernel(provisional_id),
    )
