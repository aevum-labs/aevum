"""
GET /v1/replay/{audit_id} — reconstruct a past decision. Spec Section 10.3.
"""

from __future__ import annotations

from typing import Annotated

from aevum.core.engine import Engine
from aevum.core.envelope.models import OutputEnvelope
from fastapi import APIRouter, Depends

from aevum.server.core.deps import get_actor, get_correlation_id, get_engine

router = APIRouter()


@router.get("/replay/{audit_id:path}", response_model=OutputEnvelope)
async def replay(
    audit_id: str,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> OutputEnvelope:
    """
    Reconstruct a past decision faithfully.
    audit_id must be a valid urn:aevum:audit:* identifier.
    Consent for the replay operation is checked by the kernel.
    """
    return engine.replay(
        audit_id=audit_id,
        actor=actor,
        correlation_id=correlation_id,
    )
