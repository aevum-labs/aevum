"""
GET /v1/review/{audit_id} — poll status
POST /v1/review/{audit_id}/approve — approve
POST /v1/review/{audit_id}/veto — veto
Spec Section 10.3.
"""

from __future__ import annotations

from typing import Annotated

from aevum.core.engine import Engine
from aevum.core.envelope.models import OutputEnvelope
from fastapi import APIRouter, Depends

from aevum.server.core.deps import get_actor, get_correlation_id, get_engine
from aevum.server.schemas.requests import ReviewActionRequest

router = APIRouter()


@router.get("/review/{audit_id:path}", response_model=OutputEnvelope)
async def get_review(
    audit_id: str,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> OutputEnvelope:
    """Poll the status of a pending review."""
    return engine.review(
        audit_id=audit_id,
        actor=actor,
        action=None,
        correlation_id=correlation_id,
    )


@router.post("/review/{audit_id:path}/approve", response_model=OutputEnvelope)
async def approve_review(
    audit_id: str,
    body: ReviewActionRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> OutputEnvelope:
    """Record human approval of a pending review."""
    return engine.review(
        audit_id=audit_id,
        actor=actor,
        action="approve",
        correlation_id=correlation_id,
    )


@router.post("/review/{audit_id:path}/veto", response_model=OutputEnvelope)
async def veto_review(
    audit_id: str,
    body: ReviewActionRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> OutputEnvelope:
    """Record human veto of a pending review. Veto-as-default: silence = veto."""
    return engine.review(
        audit_id=audit_id,
        actor=actor,
        action="veto",
        correlation_id=correlation_id,
    )
