"""
GET /v1/health — liveness probe. No auth required. Spec Section 10.3.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from aevum.server.schemas.responses import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """
    Health check. MUST NOT require authentication.
    Returns 200 when the server is accepting requests.
    Includes kernel status and principles sequence number.
    """
    from aevum.server import __version__

    kernel_status: dict[str, Any] = {"status": "ok"}
    principles_seq: int | None = None

    try:
        engine = request.app.state.engine
        principles_seq = getattr(engine, "principles_sequence_number", None)
        if principles_seq is None:
            sigchain = getattr(engine, "_sigchain", None)
            if sigchain is not None:
                principles_seq = getattr(sigchain, "sequence_number", None)
    except Exception:  # noqa: BLE001
        kernel_status = {"status": "degraded"}

    return HealthResponse(
        status=kernel_status["status"],
        version=__version__,
    )
