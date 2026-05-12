# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Boot-time Ed25519 verification of signed_principles.yaml.

Called once at Kernel.local() before any session opens.
If verification fails, the system halts — raising PrinciplesError.

The signed_principles.yaml file was created by tools/sign_principles.py
using pyca/cryptography Ed25519. The public key is encoded as a did:key.

did:key decoding:
  "did:key:z6Mk..." -> base58btc decode -> strip 2-byte multicodec prefix
  -> 32-byte raw Ed25519 public key -> load with pyca/cryptography

Verification:
  pub_key.verify(signature_bytes, content_bytes)
  where content_bytes = canonical_json(content_dict)
  and signature_bytes = bytes.fromhex(envelope["signature"])
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import base58
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger(__name__)


class PrinciplesError(Exception):
    """
    Raised when the signed principles cannot be verified at boot.
    The system must not continue if this is raised.
    """


@dataclasses.dataclass(frozen=True)
class Principles:
    """Verified, loaded principles. Only produced by PrinciplesVerifier.verify()."""
    format_version: str
    sequence: int
    signed_by: str       # did:key identifier
    signed_at: str       # ISO 8601
    layers: dict[str, Any]
    raw_content: dict[str, Any]

    def immutable_ids(self) -> list[str]:
        """Return IDs of all immutable principles."""
        return [
            p["id"]
            for p in self.layers.get("immutable", {}).get("principles", [])
        ]

    def regulated_ids(self) -> list[str]:
        """Return IDs of all regulated principles."""
        return [
            p["id"]
            for p in self.layers.get("regulated", {}).get("principles", [])
        ]

    def operational_ids(self) -> list[str]:
        """Return IDs of all operational principles."""
        return [
            p["id"]
            for p in self.layers.get("operational", {}).get("principles", [])
        ]


class PrinciplesVerifier:
    """
    Loads and verifies signed_principles.yaml at boot time.

    Verification steps:
      1. Load the signed envelope (YAML)
      2. Decode the did:key public key
      3. Canonicalize the content dict as JSON
      4. Verify the Ed25519 signature
      5. Verify the SHA-256 content hash matches
      6. Verify required immutable principles are present
      7. Return a Principles object

    Raises PrinciplesError on any failure.
    """

    # Required immutable principle IDs — these cannot be absent
    REQUIRED_IMMUTABLE = frozenset([
        "life_first",
        "crisis_barrier",
        "audit_trail",
        "govern_mandatory",
    ])

    def __init__(self, signed_principles_path: Path) -> None:
        self._path = signed_principles_path

    def verify(self) -> Principles:
        """
        Load and verify the signed principles file.
        Returns a Principles object on success.
        Raises PrinciplesError on any failure.
        """
        try:
            return self._do_verify()
        except PrinciplesError:
            raise
        except Exception as exc:
            raise PrinciplesError(
                f"Unexpected error verifying principles: {exc}"
            ) from exc

    def _do_verify(self) -> Principles:
        # Step 1: Load envelope
        if not self._path.exists():
            raise PrinciplesError(
                f"signed_principles.yaml not found at {self._path}. "
                "Cannot start without verified principles."
            )

        with self._path.open("r", encoding="utf-8") as f:
            envelope = yaml.safe_load(f)

        if not isinstance(envelope, dict):
            raise PrinciplesError("signed_principles.yaml is not a valid YAML mapping")

        # Step 2: Extract fields
        for field in ("signed_by", "signature", "content_sha256", "content"):
            if field not in envelope:
                raise PrinciplesError(
                    f"signed_principles.yaml missing required field: {field}"
                )

        signed_by: str = envelope["signed_by"]
        signature_hex: str = envelope["signature"]
        expected_hash: str = envelope["content_sha256"]
        content: dict[str, Any] = envelope["content"]

        # Step 3: Decode did:key -> raw Ed25519 public key
        pub_key = self._decode_did_key(signed_by)

        # Step 4: Canonicalize content
        content_bytes = self._canonical_json(content)

        # Step 5: Verify content hash
        actual_hash = hashlib.sha256(content_bytes).hexdigest()
        if actual_hash != expected_hash:
            raise PrinciplesError(
                f"Content hash mismatch in signed_principles.yaml. "
                f"Expected: {expected_hash}, Got: {actual_hash}"
            )

        # Step 6: Verify Ed25519 signature
        signature_bytes = bytes.fromhex(signature_hex)
        try:
            pub_key.verify(signature_bytes, content_bytes)
        except InvalidSignature as exc:
            raise PrinciplesError(
                "Ed25519 signature verification failed on signed_principles.yaml. "
                "The file may have been tampered with."
            ) from exc

        # Step 7: Verify required immutable principles are present
        layers = content.get("layers", {})
        immutable = layers.get("immutable", {})
        present_ids = {
            p["id"]
            for p in immutable.get("principles", [])
            if isinstance(p, dict) and "id" in p
        }
        missing = self.REQUIRED_IMMUTABLE - present_ids
        if missing:
            raise PrinciplesError(
                f"Required immutable principles missing: {sorted(missing)}"
            )

        logger.info(
            "Principles verified. Signed by: %s, Sequence: %s",
            signed_by, envelope.get("sequence", "?"),
        )

        return Principles(
            format_version=str(content.get("format_version", "2.0")),
            sequence=int(envelope.get("sequence", 1)),
            signed_by=signed_by,
            signed_at=str(envelope.get("signed_at", "")),
            layers=layers,
            raw_content=content,
        )

    @staticmethod
    def _decode_did_key(did_key: str) -> Ed25519PublicKey:
        """
        Decode a did:key string to an Ed25519PublicKey.

        did:key format: did:key:z<base58btc(multicodec_prefix + raw_pub_bytes)>
        Ed25519 multicodec prefix: 0xed 0x01
        """
        if not did_key.startswith("did:key:z"):
            raise PrinciplesError(
                f"signed_by field is not a valid did:key: {did_key!r}"
            )

        # Strip "did:key:z" — the "z" is the multibase prefix for base58btc
        b58_part = did_key[len("did:key:z"):]
        try:
            decoded = base58.b58decode(b58_part)
        except Exception as exc:
            raise PrinciplesError(
                f"Failed to base58-decode did:key: {exc}"
            ) from exc

        # Strip 2-byte multicodec prefix [0xed, 0x01]
        if len(decoded) < 2 or decoded[0] != 0xed or decoded[1] != 0x01:
            raise PrinciplesError(
                "did:key does not have Ed25519 multicodec prefix (0xed 0x01)"
            )

        raw_pub = decoded[2:]
        if len(raw_pub) != 32:
            raise PrinciplesError(
                f"Ed25519 public key should be 32 bytes, got {len(raw_pub)}"
            )

        return Ed25519PublicKey.from_public_bytes(raw_pub)

    @staticmethod
    def _canonical_json(data: dict[str, Any]) -> bytes:
        """Produce deterministic JSON bytes matching the signing tool output."""
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
