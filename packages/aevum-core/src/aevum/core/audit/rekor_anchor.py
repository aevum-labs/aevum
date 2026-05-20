# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Optional Sigstore Rekor v2 anchoring for the Aevum sigchain.

The Rekor public transparency log provides an external, publicly verifiable
record that a given Merkle root existed at a given time.

This is optional — the sigchain is valid without Rekor. Rekor adds
a second external timestamp and makes the chain root publicly verifiable.

The circuit breaker ensures Rekor failures never block sigchain operations.

Rekor v2 API (rekor-tiles):
  POST <AEVUM_REKOR_URL>/api/v2/log/entries
  Content-Type: application/json
  Body: hashedrekord or dsse entry

The Rekor endpoint is configured via the AEVUM_REKOR_URL environment variable.
No default URL is hardcoded. Set AEVUM_REKOR_URL for production deployments.
For self-hosted Rekor, see docs/deployment/rekor-self-hosted.md.

Usage:
  anchor = RekorAnchor()   # URL from AEVUM_REKOR_URL; disabled if unset
  entry = anchor.anchor_chain_root(
      chain_root_hash="abc123...",
      ed25519_sig=dual_sig.ed25519_sig,
      ed25519_pub=dual_sig.ed25519_pub,
  )
  # entry is None if Rekor is unavailable or not configured (circuit breaker)
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

from aevum.core.audit.signing_config import SigningConfig
from aevum.core.exceptions import RekorVerificationError

logger = logging.getLogger(__name__)

# REKOR_URL is resolved from SigningConfig (reads AEVUM_REKOR_URL env var).
# None means Rekor anchoring is disabled for this process.
REKOR_URL: str | None = SigningConfig.from_env().rekor_url
REKOR_TIMEOUT = 15.0


def _verify_rekor_entry(entry: dict[str, Any], expected_sha256: str) -> None:
    """
    Assert the Rekor entry references the expected artifact hash.

    Mitigation for Cosign CVE-2026-22703: a malicious Rekor server (or MITM)
    could return an entry for a *different* artifact. Verifying locally that
    the returned inclusion proof references the correct digest closes this gap.

    entry: Rekor API response dict (keys are UUIDs mapping to entry objects)
    expected_sha256: hex-encoded SHA-256 digest of the anchored artifact

    Raises RekorVerificationError if the entry does not reference expected_sha256.
    """
    for _uuid, record in entry.items():
        body_b64 = record.get("body", "")
        if not body_b64:
            raise RekorVerificationError("Rekor entry has no body field")

        try:
            body = json.loads(base64.b64decode(body_b64))
        except Exception as exc:  # noqa: BLE001
            raise RekorVerificationError(f"Could not decode Rekor entry body: {exc}") from exc

        kind = body.get("kind", "")

        # hashedrekord: spec.data.hash.value
        if kind == "hashedrekord":
            actual = body.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
        # dsse: spec.payloadHash.value
        elif kind == "dsse":
            actual = body.get("spec", {}).get("payloadHash", {}).get("value", "")
        else:
            raise RekorVerificationError(f"Unknown Rekor entry kind: {kind!r}")

        if actual.lower() != expected_sha256.lower():
            raise RekorVerificationError(
                f"Rekor entry hash mismatch: got {actual!r}, expected {expected_sha256!r}"
            )
        return  # first entry verified — done

    raise RekorVerificationError("Rekor response contained no entries")


class RekorAnchor:
    """
    Anchors the Aevum sigchain Merkle root in a Rekor v2 transparency log.
    Circuit breaker: always returns None on failure, never raises.
    Disabled automatically when AEVUM_REKOR_URL is not configured.
    """

    def __init__(
        self,
        rekor_url: str | None = None,
        timeout: float = REKOR_TIMEOUT,
        enabled: bool = True,
    ) -> None:
        cfg = SigningConfig(rekor_url=rekor_url) if rekor_url else SigningConfig.from_env()
        self._url = cfg.rekor_url or ""
        self._timeout = timeout
        # Auto-disable when no URL is configured
        self._enabled = enabled and cfg.is_configured()
        if enabled and not cfg.is_configured():
            logger.debug(
                "RekorAnchor: AEVUM_REKOR_URL not set — Rekor anchoring disabled. "
                "Set AEVUM_REKOR_URL to enable transparency log submission."
            )

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

        Returns: Rekor response dict on success, None on failure or if disabled.
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
        POST a hashedrekord entry to Rekor v2 and verify the returned entry.

        The hashedrekord type records a hash + signature without the full artifact.
        After a successful POST, _verify_rekor_entry() checks that the returned
        entry references chain_root_hash (CVE-2026-22703 mitigation).
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
            result: dict[str, Any] = response.json()
            _verify_rekor_entry(result, chain_root_hash)
            logger.info(
                "Rekor anchor success for chain root %s...",
                chain_root_hash[:8],
            )
            return result

        logger.warning(
            "Rekor returned HTTP %d for chain root %s...",
            response.status_code, chain_root_hash[:8],
        )
        return None
