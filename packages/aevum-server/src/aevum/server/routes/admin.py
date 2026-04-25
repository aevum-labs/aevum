"""
/_aevum/v1/* — admin API (operator-only surface). Spec Section 10.4.
Phase 3b: stubs. Real implementation arrives with complication lifecycle (Phase 6).
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from aevum.server.core.deps import get_actor

router = APIRouter()


@router.get("/complications")
async def list_complications(
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    """List all complications with state. Phase 6 implementation."""
    return {"complications": [], "note": "Phase 6 placeholder"}


@router.post("/complications/{complication_id}/approve")
async def approve_complication(
    complication_id: str,
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"approved": False, "note": "Phase 6 placeholder"}


@router.post("/complications/{complication_id}/suspend")
async def suspend_complication(
    complication_id: str,
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"suspended": False, "note": "Phase 6 placeholder"}


@router.get("/complications/{complication_id}/health")
async def complication_health(
    complication_id: str,
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"healthy": True, "note": "Phase 6 placeholder"}


@router.get("/usage")
async def get_usage(
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"usage": {}, "note": "Phase 6 placeholder"}


@router.get("/federation/peers")
async def list_federation_peers(
    actor: Annotated[str, Depends(get_actor)],
) -> dict[str, Any]:
    return {"peers": [], "note": "Phase 8 placeholder"}
