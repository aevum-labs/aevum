"""
aevum.core.audit.signer — Pluggable signing interface.

The signing key MUST live outside the agent's trust boundary for:
  - FDA 21 CFR §11.10(e) "independently record" compliance
  - EU AI Act Art. 12 tamper-evidence
  - HIPAA §164.312(b) audit control integrity

The default InProcessSigner auto-generates an Ed25519 key at startup.
For regulated deployments: use VaultTransitSigner (aevum-sdk) or implement
this ABC against your KMS / PKCS#11 HSM.

Signing semantics: sign(digest) where digest = SHA3-256(canonical_payload).
The signer receives a 32-byte digest — NOT the raw message. This enables
prehashed signing against external systems (Vault Transit prehashed=true,
AWS KMS MessageType=DIGEST) without exposing event content.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod


class Signer(ABC):
    """
    Abstract signing interface. Every implementation must be safe to
    call from multiple threads (append() holds _lock, but the signer
    is the shared resource across threads).
    """

    @abstractmethod
    def sign(self, digest: bytes) -> bytes:
        """
        Sign a SHA3-256 digest (32 bytes). Returns raw signature bytes.

        The digest is SHA3-256(RFC-8785-canonical-event-fields).
        The signer must NOT re-hash the input — it is already a digest.
        """
        ...

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """
        Return the raw public key bytes needed to verify signatures
        produced by this signer. For Ed25519: 32 bytes. For ECDSA P-256:
        65 bytes uncompressed. For Vault Transit: fetched from Vault key API.
        """
        ...

    @property
    @abstractmethod
    def key_id(self) -> str:
        """
        Stable, human-readable identifier for this key.
        Examples: UUID v4, Vault key name + version, KMS ARN, PKCS#11 label.
        Used as AuditEvent.signer_key_id — must be consistent across
        the lifetime of this key to allow chain verification.
        """
        ...

    @property
    def provenance(self) -> str:
        """
        Trust-boundary declaration. Recorded in session.start payload.
        Override in external implementations.
        Valid values: 'in-process' | 'vault-transit' | 'aws-kms' |
                      'pkcs11' | 'external'
        """
        return "in-process"


class InProcessSigner(Signer):
    """
    Default signer. Generates an Ed25519 key in-process at startup.

    Trust boundary: the key is held in Python heap memory — the same
    process as the agent. This satisfies tamper-DETECTION (hash chain
    integrity) but NOT tamper-PREVENTION against a compromised agent.

    For regulated environments that require 'independently record' per
    FDA §11.10(e), use an external signer (VaultTransitSigner or KMS).

    Backwards-compatible with Sigchain(private_key=key) usage:
        signer = InProcessSigner(private_key=existing_key, key_id=existing_id)
    """

    def __init__(
        self,
        private_key: object | None = None,  # Ed25519PrivateKey | None
        key_id: str | None = None,
        provenance_override: str | None = None,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        if private_key is None:
            self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
            self._provenance = "in-process"
        else:
            if not isinstance(private_key, Ed25519PrivateKey):
                raise TypeError(
                    f"private_key must be Ed25519PrivateKey, got {type(private_key)}"
                )
            self._private_key = private_key
            self._provenance = provenance_override or "external"

        self._key_id: str = key_id or str(uuid.uuid4())

    def sign(self, digest: bytes) -> bytes:
        """Sign the SHA3-256 digest using Ed25519."""
        # Ed25519 in the cryptography library always applies SHA-512
        # internally to the message, so we sign the digest as a 32-byte
        # message. The verification must also pass the digest as message.
        return self._private_key.sign(digest)

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def provenance(self) -> str:
        return self._provenance
