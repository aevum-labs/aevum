"""
FastAPI shared dependencies.
Injected via Depends() into route handlers.
"""

from __future__ import annotations

from typing import Annotated

from aevum.core.engine import Engine
from fastapi import Header, Request

from aevum.server.core.config import Settings
from aevum.server.core.security import require_api_key


def get_engine(request: Request) -> Engine:
    """Extract Engine from app state (set in create_app)."""
    return request.app.state.engine  # type: ignore[no-any-return]


def get_settings(request: Request) -> Settings:
    """Extract Settings from app state."""
    return request.app.state.settings  # type: ignore[no-any-return]


def get_actor(
    request: Request,
    x_aevum_key: Annotated[str | None, Header()] = None,
) -> str:
    """
    Validate auth and return actor identity.
    Actor is the API key value — a proxy for authenticated identity.
    OIDC integration (Phase 7) will replace this with real identity resolution.
    """
    settings = request.app.state.settings
    return require_api_key(x_aevum_key, settings.api_key)


def get_correlation_id(
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> str:
    """Return client-provided or server-generated correlation ID."""
    import uuid
    return x_request_id or str(uuid.uuid4())
