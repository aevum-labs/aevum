"""
/_aevum/v1/* — admin API. Phase 6: real complication lifecycle endpoints.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aevum.core.engine import Engine
from aevum.core.exceptions import ComplicationError
from aevum.server.core.deps import get_actor, get_engine

router = APIRouter()


class ApproveRequest(BaseModel):
    pass


class SuspendRequest(BaseModel):
    pass


@router.get("/complications")
async def list_complications(
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """List all complications with their current lifecycle state."""
    return {"complications": engine.list_complications()}


@router.post("/complications/{complication_id}/approve")
async def approve_complication(
    complication_id: str,
    body: ApproveRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """Approve a PENDING complication → ACTIVE."""
    try:
        engine.approve_complication(complication_id)
        return {"approved": True, "name": complication_id}
    except ComplicationError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"type": "https://aevum.build/problems/complication-error",
                    "title": "Complication Error", "status": 409, "detail": str(e)},
        ) from e


@router.post("/complications/{complication_id}/suspend")
async def suspend_complication(
    complication_id: str,
    body: SuspendRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """Suspend an ACTIVE complication."""
    try:
        engine.suspend_complication(complication_id)
        return {"suspended": True, "name": complication_id}
    except ComplicationError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"type": "https://aevum.build/problems/complication-error",
                    "title": "Complication Error", "status": 409, "detail": str(e)},
        ) from e


@router.get("/complications/{complication_id}/health")
async def complication_health(
    complication_id: str,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """Check health of a specific complication."""
    complications = engine.list_complications()
    if complication_id not in complications:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"type": "https://aevum.build/problems/complication-not-found",
                    "title": "Not Found", "status": 404,
                    "detail": f"Complication '{complication_id}' not found"},
        )
    entry = complications[complication_id]
    return {
        "name": complication_id,
        "state": entry["state"],
        "healthy": entry["state"] == "ACTIVE",
    }


@router.get("/usage")
async def get_usage(
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"usage": {}, "note": "Phase 9 placeholder"}


@router.get("/federation/peers")
async def list_federation_peers(
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"peers": [], "note": "Phase 8 placeholder"}
