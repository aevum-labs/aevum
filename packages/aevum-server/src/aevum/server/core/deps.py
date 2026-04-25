"""
FastAPI shared dependencies.
Injected via Depends() into route handlers.
"""

from __future__ import annotations

from typing import Annotated, Any

from aevum.core.engine import Engine
from fastapi import Header, HTTPException, Request, status

from aevum.server.core.config import Settings
from aevum.server.core.security import require_api_key


def get_engine(request: Request) -> Engine:
    """Extract Engine from app state (set in create_app)."""
    return request.app.state.engine  # type: ignore[no-any-return]


def get_settings(request: Request) -> Settings:
    """Extract Settings from app state."""
    return request.app.state.settings  # type: ignore[no-any-return]


async def get_actor(
    request: Request,
    x_aevum_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """
    Validate auth and return actor identity.

    Precedence:
      1. Authorization: Bearer <token>  →  resolved via installed OIDC complication
         (fail-closed: rejects Bearer if no OIDC complication is active)
      2. X-Aevum-Key header             →  API key validation

    The actor string returned is used throughout the kernel as the principal
    identity for consent and audit purposes.
    """
    settings: Settings = request.app.state.settings
    engine: Engine = request.app.state.engine

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        oidc_comp = engine.get_active_complication_by_capability("oidc-validation")
        if oidc_comp is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "type": "https://aevum.build/problems/authentication-required",
                    "title": "Authentication Required",
                    "status": 401,
                    "detail": "Bearer token presented but no OIDC complication is active.",
                },
                headers={"Content-Type": "application/problem+json"},
            )
        result: dict[str, Any] = await oidc_comp.run(
            {"metadata": {"bearer_token": token}}, {}
        )
        if not result.get("oidc_validated"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "type": "https://aevum.build/problems/authentication-required",
                    "title": "Authentication Required",
                    "status": 401,
                    "detail": result.get("reason", "Bearer token validation failed."),
                },
                headers={"Content-Type": "application/problem+json"},
            )
        actor: str = result["resolved_actor"]
        return actor

    return require_api_key(x_aevum_key, settings.api_key)


def get_correlation_id(
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> str:
    """Return client-provided or server-generated correlation ID."""
    import uuid
    return x_request_id or str(uuid.uuid4())
