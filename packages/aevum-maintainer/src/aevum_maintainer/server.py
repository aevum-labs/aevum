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

POST /v1/ingest/scan-results receives OIDC-verified scan results from GitHub
Actions and records them as governed ingest operations in the sigchain.
"""
import datetime
import json
import logging
import time
import uuid
from typing import Annotated, Any

import httpx
import jwt
from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

from aevum_maintainer.compliance_pack import _safe_version, build_pack_payload

logger = logging.getLogger(__name__)

# Dwell time below this threshold triggers an automation_bias_warning in the sigchain.
_BIAS_WARNING_THRESHOLD_SECONDS = 30.0

# GitHub Actions OIDC constants.
_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_GITHUB_JWKS_URL = f"{_GITHUB_OIDC_ISSUER}/.well-known/jwks"
_OIDC_AUDIENCE = "aevum-maintainer"
_EXPECTED_REPO = "aevum-labs/aevum"

# ---------------------------------------------------------------------------
# OIDC verification (GitHub Actions)
# ---------------------------------------------------------------------------


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch GitHub Actions OIDC JWKS. Isolated for testability."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(_GITHUB_JWKS_URL)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result


async def verify_github_oidc_token(token: str) -> dict[str, Any]:
    """
    Verify a GitHub Actions OIDC token against the JWKS endpoint.
    Returns decoded claims on success. Raises HTTPException on failure.
    """
    jwks = await _fetch_jwks()
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid OIDC token: {exc}") from exc

    kid = header.get("kid")
    public_key: Any = None
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
            break

    if public_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="No matching key in JWKS for token kid")

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=_OIDC_AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid OIDC token: {exc}") from exc

    repo = claims.get("repository", "")
    if repo != _EXPECTED_REPO:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Token from unexpected repo: {repo!r}")

    return claims


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


class ScanIngestResponse(BaseModel):
    audit_id: str
    status: str


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(engine: Engine | None = None) -> FastAPI:
    """Create the maintainer FastAPI application."""
    _engine = engine or Engine()
    app = FastAPI(title="aevum-maintainer", version="0.4.0")

    # Bootstrap consent grant so ingest() does not 500 on first call.
    # subject_id="aevum-maintainer" covers all governed operations this server performs.
    _boot_grant = ConsentGrant(
        grant_id=str(uuid.uuid4()),
        subject_id="aevum-maintainer",
        grantee_id="maintainer",
        operations=["ingest", "query", "replay"],
        purpose="aevum-maintainer governed operations",
        classification_max=0,
        granted_at=datetime.datetime.now(datetime.UTC).isoformat(),
        expires_at="2099-12-31T00:00:00Z",
        authorization_ref="system-bootstrap",
    )
    _engine.add_consent_grant(_boot_grant)

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

    @app.post("/v1/ingest/scan-results", response_model=ScanIngestResponse)
    async def ingest_scan_results(
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Receive OIDC-verified scan results from GitHub Actions and record them
        in the Aevum sigchain as a governed ingest operation.

        Authorization: Bearer <GitHub Actions OIDC token>
        The token must be issued for the aevum-labs/aevum repository.
        """
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header (expected Bearer token)",
            )
        token = auth_header.removeprefix("Bearer ")
        claims = await verify_github_oidc_token(token)
        body = await request.json()
        provenance: dict[str, Any] = {
            "source_id": "github-actions",
            "ingest_audit_id": "oidc-verified",
            "chain_of_custody": ["github-actions", "aevum-maintainer"],
            "classification": 0,
        }
        envelope = engine.ingest(
            data={"scan_results": body, "oidc_claims": claims},
            actor=claims.get("repository", "github-actions"),
            provenance=provenance,
            purpose="aevum-maintainer governed operations",
            subject_id="aevum-maintainer",
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "ingest failed")),
            )
        return ScanIngestResponse(audit_id=envelope.audit_id, status=envelope.status)

    return app
