# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Optional Sigstore Rekor v2 anchoring for the Aevum sigchain.

The Rekor public transparency log provides an external, publicly verifiable
record that a given Merkle root existed at a given time.

This is optional — the sigchain is valid without Rekor. Rekor adds
a second external timestamp and makes the chain root publicly verifiable.

The circuit breaker ensures Rekor failures never block sigchain operations.

Rekor v2 API (Sigstore production):
  POST https://rekor.sigstore.dev/api/v2/log/entries
  Content-Type: application/json
  Body: DSSE envelope with hashedrekord or dsse type

Note: Rekor v2 uses DSSE (Dead Simple Signing Envelope) format.
This implementation uses the dsse entry type with Ed25519 signature.

Usage:
  anchor = RekorAnchor()
  entry = anchor.anchor_chain_root(
      chain_root_hash="abc123...",
      ed25519_sig=dual_sig.ed25519_sig,
      ed25519_pub=dual_sig.ed25519_pub,
  )
  # entry is None if Rekor is unavailable (circuit breaker)
"""
from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

REKOR_URL = "https://rekor.sigstore.dev/api/v2/log/entries"
REKOR_TIMEOUT = 15.0


class RekorAnchor:
    """
    Anchors the Aevum sigchain Merkle root in the Sigstore Rekor log.
    Circuit breaker: always returns None on failure, never raises.
    """

    def __init__(
        self,
        rekor_url: str = REKOR_URL,
        timeout: float = REKOR_TIMEOUT,
        enabled: bool = True,
    ) -> None:
        self._url = rekor_url
        self._timeout = timeout
        self._enabled = enabled

    def anchor_chain_root(
        self,
        chain_root_hash: str,
        ed25519_sig: bytes,
        ed25519_pub: bytes,
    ) -> dict[str, Any] | None:
        """
        Anchor a chain root hash in Rekor.

        chain_root_hash: hex-encoded SHA-256 Merkle root
        ed25519_sig: Ed25519 signature over the hash bytes
        ed25519_pub: Ed25519 public key (32 bytes raw)

        Returns: Rekor response dict on success, None on failure.
        The circuit breaker ensures this never raises.
        """
        if not self._enabled:
            return None

        try:
            return self._post_to_rekor(chain_root_hash, ed25519_sig, ed25519_pub)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Rekor anchoring failed (non-blocking): %s. "
                "Chain root %s... not anchored in transparency log.",
                exc, chain_root_hash[:8],
            )
            return None

    def _post_to_rekor(
        self,
        chain_root_hash: str,
        ed25519_sig: bytes,
        ed25519_pub: bytes,
    ) -> dict[str, Any] | None:
        """
        POST a hashedrekord entry to Rekor.
        The hashedrekord type is the simplest Rekor entry type —
        it records a hash + signature without the full artifact.
        """
        sig_b64 = base64.b64encode(ed25519_sig).decode("ascii")
        pub_b64 = base64.b64encode(ed25519_pub).decode("ascii")

        entry = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": sig_b64,
                    "publicKey": {
                        "content": pub_b64,
                    },
                },
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": chain_root_hash,
                    },
                },
            },
        }

        response = httpx.post(
            self._url,
            json=entry,
            headers={"Content-Type": "application/json"},
            timeout=self._timeout,
            follow_redirects=True,
        )

        if response.status_code in (200, 201):
            logger.info(
                "Rekor anchor success for chain root %s...",
                chain_root_hash[:8],
            )
            return response.json()  # type: ignore[no-any-return]

        logger.warning(
            "Rekor returned HTTP %d for chain root %s...",
            response.status_code, chain_root_hash[:8],
        )
        return None
