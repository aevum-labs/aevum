# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
TransparencyBackend protocol and concrete implementations.

NullBackend:      Dev mode — no network calls.
RekorV2Backend:   Wraps the existing PublishComplication Rekor v2 submission path.
ScittTsBackend:   Stub for future SCITT ScrAPI (draft-ietf-scitt-scrapi).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from typing import Protocol, runtime_checkable


@runtime_checkable
class TransparencyBackend(Protocol):
    def submit(self, receipt_cbor: bytes) -> str:
        """
        Submit a COSE_Sign1 receipt to the transparency service.
        Returns an opaque receipt reference (URL, log entry ID, or UUID).
        Must be idempotent — submitting the same receipt twice is safe.
        """
        ...


class NullBackend:
    """Dev mode backend. No network calls. Returns a deterministic UUID."""

    def submit(self, receipt_cbor: bytes) -> str:
        return str(uuid.UUID(bytes=hashlib.sha3_256(receipt_cbor).digest()[:16]))


class RekorV2Backend:
    """
    Wraps the existing PublishComplication Rekor v2 submission path.

    Uses SHA-256 (NOT SHA3-256) for the hashedrekord digest — Rekor v2
    requires SHA-256 per the hashedrekord spec. The chain's internal
    integrity uses SHA3-256; this is the external witness SHA-256.
    This distinction is documented in complication.py:
      "Using SHA-256 (not SHA3-256) because Rekor's hashedrekord spec requires SHA-256."
    """

    def __init__(self, rekor_url: str | None = None) -> None:
        self._url = rekor_url or os.environ.get(
            "AEVUM_REKOR_URL", "https://rekor.sigstore.dev"
        )

    def submit(self, receipt_cbor: bytes) -> str:
        """
        Submit COSE_Sign1 receipt bytes to Rekor v2 as a hashedrekord.
        Uses SHA-256 digest of the receipt_cbor bytes.
        Returns the Rekor log entry UUID.
        """
        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "aevum-publish requires httpx for Rekor submission. "
                "Install with: pip install aevum-publish[rekor]"
            ) from exc

        from aevum.core.audit.rekor_anchor import _verify_rekor_entry

        sha256_digest = hashlib.sha256(receipt_cbor).hexdigest()

        body = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": sha256_digest,
                    }
                },
            },
        }

        resp = httpx.post(
            f"{self._url.rstrip('/')}/api/v2/log/entries",
            json=body,
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()

        # CVE-2026-22703 mitigation: verify returned entry references submitted digest
        _verify_rekor_entry(data, sha256_digest)

        return str(next(iter(data)))


class ScittTsBackend:
    """
    Stub for future SCITT Transparency Service via ScrAPI.
    Raises NotImplementedError with a clear message.
    """

    def __init__(self, scrapi_url: str) -> None:
        self._url = scrapi_url

    def submit(self, receipt_cbor: bytes) -> str:
        raise NotImplementedError(
            "SCITT ScrAPI (draft-ietf-scitt-scrapi) not yet GA. "
            "Use RekorV2Backend in production. "
            "Track: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/"
        )
