"""
HTTP response schemas.
Most routes return OutputEnvelope directly.
These are supplementary schemas for non-envelope responses.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """GET /v1/health response."""
    status: str
    version: str


class ProblemDetail(BaseModel):
    """RFC 9457 Problem Details. Content-Type: application/problem+json."""
    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None
    request_id: str | None = None
    audit_id: str | None = None
    extensions: dict[str, Any] | None = None
