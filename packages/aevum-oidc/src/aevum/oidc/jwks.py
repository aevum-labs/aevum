"""
JWKS fetching and caching with TTL.
Avoids hitting the IDP on every request.
"""

from __future__ import annotations

import time
from typing import Any

import httpx


class JwksCache:
    """
    Fetch and cache JWKS from an OIDC provider.

    Args:
        jwks_uri: URL of the JWKS endpoint
        ttl_seconds: How long to cache keys before re-fetching (default 3600)
    """

    def __init__(self, jwks_uri: str, ttl_seconds: int = 3600) -> None:
        self._jwks_uri = jwks_uri
        self._ttl = ttl_seconds
        self._keys: list[dict[str, Any]] = []
        self._fetched_at: float = 0.0
        self._client: httpx.Client | None = None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=10.0)
        return self._client

    def get_keys(self) -> list[dict[str, Any]]:
        """Return cached keys, re-fetching if TTL has elapsed."""
        now = time.monotonic()
        if now - self._fetched_at > self._ttl or not self._keys:
            response = self._http().get(self._jwks_uri)
            response.raise_for_status()
            self._keys = response.json().get("keys", [])
            self._fetched_at = now
        return self._keys

    def invalidate(self) -> None:
        """Force re-fetch on next access."""
        self._fetched_at = 0.0
        self._keys = []
