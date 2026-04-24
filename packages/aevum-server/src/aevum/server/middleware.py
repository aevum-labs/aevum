"""
Middleware — correlation IDs, security headers, rate limit headers.
Applied to every response via app.middleware("http").
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class AevumMiddleware(BaseHTTPMiddleware):
    """
    Single middleware handling:
    1. Correlation ID propagation (X-Request-ID)
    2. Security headers on every response
    3. Rate limit info headers (headers always present; enforcement is operator concern)
    4. Request timing
    """

    def __init__(self, app: ASGIApp, rate_limit_per_minute: int = 1000) -> None:
        super().__init__(app)
        self._rate_limit = rate_limit_per_minute

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start = time.perf_counter()

        # Correlation ID
        correlation_id = request.headers.get("x-request-id") or str(uuid.uuid4())

        response: Response = await call_next(request)

        duration_ms = int((time.perf_counter() - start) * 1000)

        # Correlation ID echo
        response.headers["X-Request-ID"] = correlation_id

        # Security headers (spec Section 10.8)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = "default-src 'none'"

        # Rate limit info headers (spec Section 10.7)
        response.headers["X-RateLimit-Limit"] = str(self._rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(self._rate_limit)
        response.headers["X-RateLimit-Reset"] = "60"

        # Timing
        response.headers["X-Response-Time-Ms"] = str(duration_ms)

        return response
