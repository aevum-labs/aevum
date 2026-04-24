"""
GET /v1/health — liveness probe. No auth required. Spec Section 10.3.
"""

from __future__ import annotations

from fastapi import APIRouter

from aevum.server.schemas.responses import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """
    Health check. MUST NOT require authentication.
    Returns 200 when the server is accepting requests.
    """
    from aevum.server import __version__
    return HealthResponse(status="ok", version=__version__)
