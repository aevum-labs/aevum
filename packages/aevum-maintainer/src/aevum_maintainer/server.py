# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum Maintainer HTTP server.

Exposes a governed endpoint for triggering compliance pack generation.
Every generation call goes through engine.ingest(), producing a sigchain
entry that records who requested generation, when, and what was produced.

Also exposes structured HITL consent endpoints (/v1/consent/*) that require
explicit typed acknowledgment from reviewers — satisfying EU AI Act Article 14
automation bias obligations. Dwell time is recorded in the sigchain so auditors
can distinguish genuine human review from rubber-stamp approvals.
"""
import logging
import time
import uuid
from typing import Annotated, Any

from aevum.core.engine import Engine
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from aevum_maintainer.compliance_pack import _safe_version, build_pack_payload

logger = logging.getLogger(__name__)

# Dwell time below this threshold triggers an automation_bias_warning in the sigchain.
_BIAS_WARNING_THRESHOLD_SECONDS = 30.0

# ---------------------------------------------------------------------------
# Request / response models (module-level so FastAPI can resolve annotations)
# ---------------------------------------------------------------------------


class GenerateRequest(BaseModel):
    version: str
    # File paths are never accepted from callers. All paths inside
    # generate_manifest() are derived from hardcoded constants (CWE-22).
    actor: str = "aevum-maintainer"


class GenerateResponse(BaseModel):
    audit_id: str
    manifest_file_count: int
    version: str


class ReviewRequest(BaseModel):
    action_description: str = Field(min_length=10)
    actor: str = "maintainer"


class ReviewResponse(BaseModel):
    review_id: str
    review_requested_at: float
    audit_id: str


class StructuredApproval(BaseModel):
    """Fields the approver must explicitly provide — not defaults, not optional."""
    review_id: str
    acknowledged_intent: str = Field(min_length=10)
    acknowledged_blast_radius: str = Field(min_length=10)
    acknowledged_rollback: str = Field(min_length=10)
    reviewer_id: str = Field(min_length=1)


class ApprovalResponse(BaseModel):
    audit_id: str
    dwell_time_seconds: float
    automation_bias_warning: bool


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(engine: Engine | None = None) -> FastAPI:
    """Create the maintainer FastAPI application."""
    _engine = engine or Engine()
    app = FastAPI(title="aevum-maintainer", version="0.4.0")

    # In-memory pending reviews: review_id → {action_description, review_requested_at}
    _pending_reviews: dict[str, dict[str, Any]] = {}

    def get_engine() -> Engine:
        return _engine

    @app.post("/v1/compliance-pack/generate", response_model=GenerateResponse)
    async def generate_compliance_pack(
        req: GenerateRequest,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Generate a compliance pack and record the event in the sigchain.

        Returns the sigchain audit_id for the generation event.
        """
        try:
            safe_ver = _safe_version(req.version)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        payload = build_pack_payload(safe_ver)
        provenance: dict[str, Any] = {
            "source_id": "aevum-maintainer",
            "ingest_audit_id": "bootstrap",
            "chain_of_custody": ["aevum-maintainer"],
            "classification": 0,
        }
        envelope = engine.ingest(
            data=payload,
            actor=req.actor,
            provenance=provenance,
            purpose="compliance-pack-generation",
            subject_id="aevum-maintainer",
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "ingest failed")),
            )
        manifest = payload["manifest"]
        return GenerateResponse(
            audit_id=envelope.audit_id,
            manifest_file_count=len(manifest.get("files", {})),
            version=req.version,
        )

    @app.post("/v1/consent/review", response_model=ReviewResponse)
    async def create_review(
        req: ReviewRequest,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Create a pending review request. Returns a review_id the approver uses to submit
        structured acknowledgment. Records review_requested_at in the sigchain.
        """
        review_id = str(uuid.uuid4())
        requested_at = time.time()
        _pending_reviews[review_id] = {
            "action_description": req.action_description,
            "review_requested_at": requested_at,
        }
        envelope = engine.commit(
            event_type="consent.review_requested",
            payload={
                "review_id": review_id,
                "action_description": req.action_description,
                "review_requested_at": requested_at,
            },
            actor=req.actor,
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "commit failed")),
            )
        return ReviewResponse(
            review_id=review_id,
            review_requested_at=requested_at,
            audit_id=envelope.audit_id,
        )

    @app.post("/v1/consent/approve", response_model=ApprovalResponse)
    async def approve_review(
        req: StructuredApproval,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Submit structured approval for a pending review. Requires explicit typed
        acknowledgment of intent, blast radius, and rollback plan — not just a click.

        Dwell time (seconds between review creation and approval) is recorded in the
        sigchain. Approvals under 30 seconds set automation_bias_warning=True,
        making automation bias visible in the audit record.
        """
        pending = _pending_reviews.pop(req.review_id, None)
        if pending is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"review_id {req.review_id!r} not found or already consumed",
            )

        dwell_time = time.time() - pending["review_requested_at"]
        automation_bias_warning = dwell_time < _BIAS_WARNING_THRESHOLD_SECONDS

        if automation_bias_warning:
            logger.warning(
                "HITL automation bias: review_id=%s approved in %.1fs (< %ss threshold). "
                "audit_warning=True recorded in sigchain.",
                req.review_id,
                dwell_time,
                _BIAS_WARNING_THRESHOLD_SECONDS,
            )

        envelope = engine.commit(
            event_type="consent.approved",
            payload={
                "review_id": req.review_id,
                "acknowledged_intent": req.acknowledged_intent,
                "acknowledged_blast_radius": req.acknowledged_blast_radius,
                "acknowledged_rollback": req.acknowledged_rollback,
                "reviewer_id": req.reviewer_id,
                "dwell_time_seconds": dwell_time,
                "automation_bias_warning": automation_bias_warning,
            },
            actor=req.reviewer_id,
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "commit failed")),
            )
        return ApprovalResponse(
            audit_id=envelope.audit_id,
            dwell_time_seconds=dwell_time,
            automation_bias_warning=automation_bias_warning,
        )

    return app
