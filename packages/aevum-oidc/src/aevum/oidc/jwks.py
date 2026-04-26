"""
JWKS fetching and caching with TTL.
Phase 9: added threading.Lock for cache correctness under concurrent requests.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx


class JwksCache:
    """
    Fetch and cache JWKS from an OIDC provider.

    Thread-safe: concurrent calls reuse cached keys without double-fetching.
    """

    def __init__(self, jwks_uri: str, ttl_seconds: int = 3600) -> None:
        self._jwks_uri = jwks_uri
        self._ttl = ttl_seconds
        self._keys: list[dict[str, Any]] = []
        self._fetched_at: float = 0.0
        self._client: httpx.Client | None = None
        self._lock = threading.Lock()  # Phase 9: thread safety

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=10.0)
        return self._client

    def get_keys(self) -> list[dict[str, Any]]:
        """Return cached keys, re-fetching if TTL has elapsed. Thread-safe."""
        with self._lock:
            now = time.monotonic()
            if now - self._fetched_at > self._ttl or not self._keys:
                response = self._http().get(self._jwks_uri)
                response.raise_for_status()
                self._keys = response.json().get("keys", [])
                self._fetched_at = now
            return list(self._keys)

    def invalidate(self) -> None:
        """Force re-fetch on next access. Thread-safe."""
        with self._lock:
            self._fetched_at = 0.0
            self._keys = []
