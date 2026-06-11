# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Dual-signature engine for the Aevum sigchain.

DualSigner requires both Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204). Both algorithms
sign the same canonical bytes — hybrid mode is the only supported posture (ADR-012).
The [pqc] extra (liboqs-python) must be installed; if it is absent, generate() and
load() raise SignerUnavailableError with an actionable message.

Both algorithms sign the same canonical bytes — the caller (sigchain.new_event) is responsible
for applying RFC 8785 JCS serialisation before calling sign(), so that the bytes are identical
across all platforms and Python versions.

Algorithm choice rationale:
  Ed25519 — Fast, compact (64-byte signatures), widely audited, FIPS 186-5 approved.
             Quantum-vulnerable in the long term (Shor's algorithm can break it once
             large-scale quantum computers exist, projected 10-20 year horizon).
  ML-DSA-65 — NIST FIPS 204 (final standard). Post-quantum secure. ~3.3 KB signatures.
              Provides defense-in-depth: if Ed25519 is ever broken, ML-DSA-65 survives.

Trust boundary (see ADR-004): DualSigner's keys live in the same process as the agent.
A compromised process could re-sign forged events with both algorithms. For deployments
requiring stronger trust guarantees, use VaultTransitSigner (external signing) — it exposes
the same interface but the private key never enters the aevum-core process.

Key sizes (ML-DSA-65):
  Public key:  1,952 bytes
  Secret key:  4,032 bytes
  Signature:   3,309 bytes

Usage:
  signer = DualSigner.generate()           # new keypair (requires liboqs)
  signer = DualSigner.load(state_dir)     # load from disk (requires liboqs + PQC key files)
  signer.save(state_dir)                  # persist to disk

  sigs = signer.sign(data)                # DualSignature
  DualSigner.verify(data, sigs)           # raises SignatureError if either is invalid
"""
from __future__ import annotations

import dataclasses
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

import nacl.encoding
import nacl.exceptions
import nacl.signing

_oqs_module: Any = None  # oqs module when available, None otherwise
_OQS_AVAILABLE: bool = False
try:
    import oqs as _oqs_import
    _oqs_module = _oqs_import
    _OQS_AVAILABLE = True
except (ImportError, OSError, RuntimeError, SystemExit):
    pass


class SignatureError(Exception):
    """Raised when signature verification fails."""


class SignerUnavailableError(Exception):
    """Raised when DualSigner cannot operate because liboqs (ML-DSA-65) is unavailable.

    This is a hard error, not a warning. The hybrid posture is non-negotiable in the
    default configuration. An explicit classical-only opt-in is available in P2 (ADR-012).
    """


@dataclasses.dataclass(frozen=True)
class DualSignature:
    """A pair of signatures over the same canonical payload bytes.

    Both signatures cover the same bytes (RFC 8785 JCS canonical form of the signing_fields
    dict). This means an attacker cannot forge one signature and substitute it — both
    Ed25519 and ML-DSA-65 must be valid for the entry to be accepted by verify_chain().

    Field sizes are fixed by their respective standards: ed25519_sig 64 bytes, mldsa65_sig
    3,309 bytes, ed25519_pub 32 bytes, mldsa65_pub 1,952 bytes.
    """
    ed25519_sig: bytes     # 64 bytes
    mldsa65_sig: bytes     # 3,309 bytes
    ed25519_pub: bytes     # 32 bytes (raw)
    mldsa65_pub: bytes     # 1,952 bytes

    def to_dict(self) -> dict[str, str]:
        """Serialize to hex strings for JSON/CBOR storage."""
        return {
            "ed25519_sig": self.ed25519_sig.hex(),
            "mldsa65_sig": self.mldsa65_sig.hex(),
            "ed25519_pub": self.ed25519_pub.hex(),
            "mldsa65_pub": self.mldsa65_pub.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> DualSignature:
        """Deserialize from hex strings."""
        return cls(
            ed25519_sig=bytes.fromhex(d["ed25519_sig"]),
            mldsa65_sig=bytes.fromhex(d["mldsa65_sig"]),
            ed25519_pub=bytes.fromhex(d["ed25519_pub"]),
            mldsa65_pub=bytes.fromhex(d["mldsa65_pub"]),
        )


class DualSigner:
    """Signs data with both Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204) simultaneously.

    Both algorithms sign the same bytes. The caller must ensure the bytes are canonically
    serialised (RFC 8785 JCS) before calling sign() — this class does not apply any
    serialisation itself. Keys are persisted to a state directory; call generate() first
    to create a keypair, then save() to persist it.

    Trust boundary (see ADR-004): both private keys live in this process. A compromised
    process could forge signatures with both algorithms. For higher-trust deployments,
    replace with VaultTransitSigner, which exposes the same Signer protocol but uses an
    external Vault transit endpoint so the private key never enters this process.

    Belt-and-suspenders verification: callers should call DualSigner.verify() immediately
    after sign() to catch key corruption or library bugs at write time rather than at
    the point of audit, when remediation is no longer possible.
    """

    _ED25519_KEYFILE = "ed25519.key"
    _MLDSA65_SK_FILE = "mldsa65.sk"
    _MLDSA65_PK_FILE = "mldsa65.pk"
    _MLDSA65_ALG = "ML-DSA-65"

    def __init__(
        self,
        ed25519_signing_key: nacl.signing.SigningKey,
        mldsa65_secret_key: bytes,
        mldsa65_public_key: bytes,
    ) -> None:
        self._ed25519_sk = ed25519_signing_key
        self._mldsa65_sk = mldsa65_secret_key
        self._mldsa65_pk = mldsa65_public_key

    @property
    def ed25519_public_key(self) -> bytes:
        """Raw Ed25519 public key bytes (32 bytes)."""
        return bytes(self._ed25519_sk.verify_key)

    @property
    def mldsa65_public_key(self) -> bytes:
        """ML-DSA-65 public key bytes (1,952 bytes)."""
        return self._mldsa65_pk

    @property
    def has_pq_keys(self) -> bool:
        """Always True — DualSigner requires ML-DSA-65 keys (ADR-012)."""
        return True

    @classmethod
    def generate(cls) -> DualSigner:
        """Generate a fresh Ed25519 + ML-DSA-65 keypair.

        Raises SignerUnavailableError if liboqs is absent. Keys are not persisted
        automatically; call save() after generate().
        """
        if not _OQS_AVAILABLE:
            raise SignerUnavailableError(
                "liboqs (ML-DSA-65) is required but not available. "
                "Install the PQC backend: pip install 'aevum-core[pqc]'\n"
                "An explicit classical-only mode is available in v0.8.0 (see ADR-012)."
            )
        ed25519_sk = nacl.signing.SigningKey.generate()
        with _oqs_module.Signature(cls._MLDSA65_ALG) as signer:
            mldsa65_pk = signer.generate_keypair()
            mldsa65_sk = signer.export_secret_key()
        return cls(ed25519_sk, mldsa65_sk, mldsa65_pk)

    @classmethod
    def load(cls, state_dir: Path) -> DualSigner:
        """Load keypair from state directory.

        Raises FileNotFoundError if the Ed25519 key file is absent.
        Raises SignerUnavailableError if ML-DSA-65 key files are absent (keys were
        generated before PQC was required — delete the keys directory and run
        `aevum init` to regenerate in hybrid mode).
        """
        ed25519_key_bytes = (state_dir / cls._ED25519_KEYFILE).read_bytes()
        ed25519_sk = nacl.signing.SigningKey(ed25519_key_bytes)

        sk_file = state_dir / cls._MLDSA65_SK_FILE
        pk_file = state_dir / cls._MLDSA65_PK_FILE
        if not sk_file.exists() or not pk_file.exists():
            raise SignerUnavailableError(
                f"ML-DSA-65 key files not found in {state_dir}. "
                "Keys were generated before hybrid mode was required. "
                "Delete the keys directory and run `aevum init` to regenerate. "
                "Install the PQC backend first: pip install 'aevum-core[pqc]'\n"
                "An explicit classical-only mode is available in v0.8.0 (see ADR-012)."
            )
        mldsa65_sk = sk_file.read_bytes()
        mldsa65_pk = pk_file.read_bytes()

        return cls(ed25519_sk, mldsa65_sk, mldsa65_pk)

    def save(self, state_dir: Path) -> None:
        """Persist keys to state directory. Creates directory if needed."""
        state_dir.mkdir(parents=True, exist_ok=True)
        # Ed25519 secret key (32 raw bytes)
        ed25519_key_path = state_dir / self._ED25519_KEYFILE
        ed25519_key_path.write_bytes(bytes(self._ed25519_sk))
        ed25519_key_path.chmod(0o600)
        # ML-DSA-65 keys
        sk_path = state_dir / self._MLDSA65_SK_FILE
        sk_path.write_bytes(self._mldsa65_sk)
        sk_path.chmod(0o600)
        pk_path = state_dir / self._MLDSA65_PK_FILE
        pk_path.write_bytes(self._mldsa65_pk)
        pk_path.chmod(0o644)

    def sign(self, data: bytes) -> DualSignature:
        """Sign data with Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204). Returns DualSignature.

        Both algorithms sign the identical bytes passed in. The caller is responsible for
        ensuring data is the RFC 8785 JCS canonical form of the payload dict — the same
        bytes must be reproduced at verification time to pass verify(). Passing raw dict
        bytes without JCS canonicalisation would make signatures non-reproducible.

        After this call, immediately verify() the result (belt-and-suspenders) to detect
        key corruption or liboqs library bugs at signing time rather than at audit time.
        """
        if not _OQS_AVAILABLE:
            raise SignerUnavailableError(
                "liboqs (ML-DSA-65) is required but not available. "
                "Install the PQC backend: pip install 'aevum-core[pqc]'\n"
                "An explicit classical-only mode is available in v0.8.0 (see ADR-012)."
            )
        # Ed25519 via PyNaCl
        signed = self._ed25519_sk.sign(data)
        ed25519_sig = bytes(signed.signature)  # first 64 bytes

        # ML-DSA-65 via liboqs
        with _oqs_module.Signature(self._MLDSA65_ALG, self._mldsa65_sk) as signer:
            mldsa65_sig = signer.sign(data)

        return DualSignature(
            ed25519_sig=ed25519_sig,
            mldsa65_sig=mldsa65_sig,
            ed25519_pub=self.ed25519_public_key,
            mldsa65_pub=self.mldsa65_public_key,
        )

    @staticmethod
    def verify(data: bytes, dual_sig: DualSignature) -> None:
        """Verify both Ed25519 and ML-DSA-65 signatures over data. Both must pass.

        This is NOT an OR check — a valid Ed25519 with an invalid ML-DSA-65 is rejected,
        and vice versa. Both algorithms must independently verify the same data bytes.

        Belt-and-suspenders use: sigchain.new_event() calls verify() immediately after
        sign() to catch key corruption or liboqs library bugs at signing time. A bug that
        produces a wrong signature is better caught here (write path) than at audit time
        (read path), when remediation is impossible — the entry would be unverifiable.

        Raises:
            SignatureError: If the Ed25519 signature is invalid.
            SignatureError: If the ML-DSA-65 signature is invalid.
            SignerUnavailableError: If liboqs is not installed (required for ML-DSA-65 verify).
        """
        # Verify Ed25519
        try:
            verify_key = nacl.signing.VerifyKey(dual_sig.ed25519_pub)
            verify_key.verify(data, dual_sig.ed25519_sig)
        except nacl.exceptions.BadSignatureError as exc:
            raise SignatureError(f"Ed25519 signature invalid: {exc}") from exc

        # Verify ML-DSA-65
        if not _OQS_AVAILABLE:
            raise SignerUnavailableError(
                "liboqs (ML-DSA-65) is required but not available. "
                "Install the PQC backend: pip install 'aevum-core[pqc]'\n"
                "An explicit classical-only mode is available in v0.8.0 (see ADR-012)."
            )
        with _oqs_module.Signature("ML-DSA-65") as verifier:
            ok = verifier.verify(data, dual_sig.mldsa65_sig, dual_sig.mldsa65_pub)
        if not ok:
            raise SignatureError("ML-DSA-65 signature invalid")
