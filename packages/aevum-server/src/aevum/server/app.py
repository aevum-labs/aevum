"""
create_app — FastAPI application factory.

Usage:
    from aevum.core import Engine
    from aevum.server.app import create_app

    engine = Engine()
    app = create_app(engine)

    # Production:
    # uvicorn aevum.server.app:create_app --factory
    # gunicorn aevum.server.app:create_app -k uvicorn.workers.UvicornWorker
"""

from __future__ import annotations

import logging
from typing import Any

from aevum.core.engine import Engine
from aevum.core.exceptions import (
    AevumError,
    BarrierViolationError,
    ConsentRequiredError,
    ProvenanceRequiredError,
    ReplayNotFoundError,
    ReviewAlreadyResolvedError,
    ReviewNotFoundError,
)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aevum.server.core.config import Settings
from aevum.server.middleware import AevumMiddleware
from aevum.server.routes import admin, data, health, replay, review

logger = logging.getLogger(__name__)

# RFC 9457 problem type → HTTP status code mapping
_PROBLEM_STATUS: dict[type[AevumError], int] = {
    ConsentRequiredError: 403,
    ProvenanceRequiredError: 400,
    ReplayNotFoundError: 404,
    ReviewNotFoundError: 404,
    ReviewAlreadyResolvedError: 409,
    BarrierViolationError: 403,
}

_PROBLEM_TYPES: dict[type[AevumError], str] = {
    ConsentRequiredError: "consent-required",
    ProvenanceRequiredError: "validation-error",
    ReplayNotFoundError: "replay-not-found",
    ReviewNotFoundError: "review-not-found",
    ReviewAlreadyResolvedError: "review-already-resolved",
    BarrierViolationError: "barrier-triggered",
}


def _problem_response(
    exc: AevumError,
    status: int,
    problem_type: str,
    request_id: str | None = None,
) -> JSONResponse:
    """Return RFC 9457 application/problem+json response."""
    body: dict[str, Any] = {
        "type": f"https://aevum.build/problems/{problem_type}",
        "title": exc.__class__.__name__,
        "status": status,
        "detail": str(exc),
    }
    if request_id:
        body["request_id"] = request_id
    return JSONResponse(
        content=body,
        status_code=status,
        media_type="application/problem+json",
    )


def create_app(
    engine: Engine | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """
    Create the Aevum HTTP API FastAPI application.

    Args:
        engine: Aevum kernel instance. Creates Engine() with defaults if None.
        settings: Server settings. Reads from environment if None.

    Returns:
        Configured FastAPI application.
    """
    if engine is None:
        engine = Engine()
    if settings is None:
        settings = Settings()

    app = FastAPI(
        title="Aevum HTTP API",
        version="0.2.0",
        description="Replay-first, policy-governed context kernel — HTTP surface.",
        docs_url="/v1/docs",
        openapi_url="/v1/openapi.json",
        redoc_url=None,
    )

    # Store engine and settings on app state for dependency injection
    app.state.engine = engine
    app.state.settings = settings

    # Middleware (order matters: outermost runs first on request, last on response)
    app.add_middleware(
        AevumMiddleware,
        rate_limit_per_minute=settings.rate_limit_per_minute,
    )

    # OTel instrumentation (sanitize X-Aevum-Key from spans)
    if settings.otel_enabled:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(
                app,
                # Sanitize auth header — must NOT appear in trace exports
                excluded_urls="",
                http_capture_headers_server_request=["x-request-id"],
                http_capture_headers_server_response=["x-request-id", "x-response-time-ms"],
            )
            logger.info("OTel FastAPI instrumentation enabled")
        except ImportError:
            logger.warning("opentelemetry-instrumentation-fastapi not available")

    # Global exception handler — RFC 9457 format
    @app.exception_handler(AevumError)
    async def aevum_error_handler(request: Request, exc: AevumError) -> JSONResponse:
        request_id = request.headers.get("x-request-id")
        status = _PROBLEM_STATUS.get(type(exc), 500)
        problem_type = _PROBLEM_TYPES.get(type(exc), "internal-error")
        return _problem_response(exc, status, problem_type, request_id)

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # Never expose internal details to callers
        logger.exception("Unhandled exception in request %s %s", request.method, request.url.path)
        request_id = request.headers.get("x-request-id")
        body: dict[str, Any] = {
            "type": "https://aevum.build/problems/internal-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred.",
        }
        if request_id:
            body["request_id"] = request_id
        return JSONResponse(content=body, status_code=500, media_type="application/problem+json")

    # Routes
    app.include_router(health.router, prefix="/v1")
    app.include_router(data.router, prefix="/v1")
    app.include_router(replay.router, prefix="/v1")
    app.include_router(review.router, prefix="/v1")
    app.include_router(admin.router, prefix="/_aevum/v1")

    return app
