# SPDX-License-Identifier: Apache-2.0
"""
aevum.core.audit.signer — Pluggable signing interface.

The signing key MUST live outside the agent's trust boundary for:
  - FDA 21 CFR §11.10(e) "independently record" compliance
  - EU AI Act Art. 12 tamper-evidence
  - HIPAA §164.312(b) audit control integrity

The default InProcessSigner auto-generates an Ed25519 key at startup.
For regulated deployments: implement a custom Signer (see Signer protocol)
against your KMS / PKCS#11 HSM.

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


class VaultTransitSigner(Signer):
    """
    HashiCorp Vault Transit secrets engine signer.

    Signs SHA3-256 digests via POST /v1/transit/sign/{key_name}?prehashed=true.
    The digest is passed as base64-encoded input; Vault returns a base64url
    signature that is decoded to raw bytes.

    key_scheme: "ed25519+vault-transit"
    key_id:     "{vault_addr}/v1/transit/keys/{key_name}" (stable across rotations)

    Authentication: VAULT_TOKEN environment variable (or token= constructor arg).
    If VAULT_ADDR is unset, defaults to "http://127.0.0.1:8200".

    For production use, configure Vault Transit with an ed25519 key type:
        vault secrets enable transit
        vault write transit/keys/aevum-signing type=ed25519

    Requires: httpx (pip install httpx)

    Test procedure against a Vault dev instance:
        vault server -dev &
        export VAULT_ADDR=http://127.0.0.1:8200
        export VAULT_TOKEN=root
        vault secrets enable transit
        vault write transit/keys/aevum-signing type=ed25519
        python -c "from aevum.core.audit.signer import VaultTransitSigner; ..."
    """

    _KEY_SCHEME = "ed25519+vault-transit"

    def __init__(
        self,
        key_name: str,
        *,
        vault_addr: str | None = None,
        token: str | None = None,
        key_version: int | None = None,
        timeout: float = 5.0,
    ) -> None:
        import os

        self._key_name = key_name
        self._vault_addr = (vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
        self._token = token or os.environ.get("VAULT_TOKEN", "")
        self._key_version = key_version
        self._timeout = timeout
        self._key_id_str = f"{self._vault_addr}/v1/transit/keys/{key_name}"
        self._public_key_cache: bytes | None = None

    def sign(self, digest: bytes) -> bytes:
        """
        Sign a SHA3-256 digest via Vault Transit prehashed=true.
        Returns raw 64-byte Ed25519 signature.
        """
        import base64

        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "VaultTransitSigner requires httpx: pip install httpx"
            ) from exc

        input_b64 = base64.b64encode(digest).decode()
        body: dict[str, object] = {
            "input": input_b64,
            "prehashed": True,
            "signature_algorithm": "pkcs1v15",  # ignored for ed25519; required for rsa
        }
        if self._key_version is not None:
            body["key_version"] = self._key_version

        url = f"{self._vault_addr}/v1/transit/sign/{self._key_name}"
        headers = {"X-Vault-Token": self._token}

        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(url, json=body, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Vault Transit sign failed: HTTP {resp.status_code} — {resp.text}"
                )
            data = resp.json()

        # Vault returns "vault:v{N}:{base64url-signature}"
        sig_field: str = data["data"]["signature"]
        sig_b64 = sig_field.split(":")[-1]
        # Add padding if needed for standard base64 decoding
        padding = 4 - len(sig_b64) % 4
        if padding != 4:
            sig_b64 += "=" * padding
        return base64.urlsafe_b64decode(sig_b64)

    def public_key_bytes(self) -> bytes:
        """
        Fetch the Ed25519 public key from Vault Transit keys API.
        Result is cached after the first call.
        """
        if self._public_key_cache is not None:
            return self._public_key_cache

        import base64

        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "VaultTransitSigner requires httpx: pip install httpx"
            ) from exc

        url = f"{self._vault_addr}/v1/transit/keys/{self._key_name}"
        headers = {"X-Vault-Token": self._token}

        with httpx.Client(timeout=self._timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Vault Transit key fetch failed: HTTP {resp.status_code} — {resp.text}"
                )
            data = resp.json()

        # Vault returns keys indexed by version number
        keys = data["data"]["keys"]
        if self._key_version is not None:
            key_entry = keys[str(self._key_version)]
        else:
            # latest version
            latest = str(data["data"]["latest_version"])
            key_entry = keys[latest]

        # Ed25519 public key is in "public_key" as PEM or base64
        pub_raw = key_entry.get("public_key", "")
        if pub_raw.startswith("-----"):
            # PEM format — extract raw bytes
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
            pub_obj = load_pem_public_key(pub_raw.encode())
            raw = pub_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            raw = base64.b64decode(pub_raw)

        self._public_key_cache = raw
        return raw

    @property
    def key_id(self) -> str:
        return self._key_id_str

    @property
    def provenance(self) -> str:
        return "vault-transit"

    @property
    def key_scheme(self) -> str:
        return self._KEY_SCHEME
