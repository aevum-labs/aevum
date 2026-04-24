"""
Authentication — X-Aevum-Key header validation.

Phase 3b: API key only.
OIDC bearer token support arrives with aevum-oidc (Phase 7).
"""

from __future__ import annotations

from fastapi import HTTPException, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-Aevum-Key", auto_error=False)


def require_api_key(
    api_key_value: str | None,
    configured_key: str,
) -> str:
    """
    Validate the X-Aevum-Key header.
    Returns the key value (used as actor identity) if valid.
    Raises 401 if absent or invalid.
    """
    if not api_key_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://aevum.build/problems/authentication-required",
                "title": "Authentication Required",
                "status": 401,
                "detail": "X-Aevum-Key header is required.",
            },
            headers={"Content-Type": "application/problem+json"},
        )
    if api_key_value != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://aevum.build/problems/authentication-required",
                "title": "Authentication Required",
                "status": 401,
                "detail": "Invalid API key.",
            },
            headers={"Content-Type": "application/problem+json"},
        )
    return api_key_value
