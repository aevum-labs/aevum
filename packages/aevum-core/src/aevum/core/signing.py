# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Dual-signature engine for the Aevum sigchain.

Provides Ed25519 (via PyNaCl) and ML-DSA-65 (via liboqs-python) signatures
on every sigchain entry from genesis. Both signatures must be present and
valid for a chain entry to be accepted.

Ed25519: Fast, compact (64 bytes), widely supported. Quantum-vulnerable long-term.
ML-DSA-65: NIST FIPS 204. Post-quantum secure. 3,309-byte signatures.
The combination provides defense-in-depth: one algorithm must survive.

Key sizes (ML-DSA-65):
  Public key:  1,952 bytes
  Secret key:  4,032 bytes
  Signature:   3,309 bytes

Usage:
  signer = DualSigner.generate()           # new keypair
  signer = DualSigner.load(state_dir)     # load from disk
  signer.save(state_dir)                  # persist to disk

  sigs = signer.sign(data)                # DualSignature
  signer.verify(data, sigs)               # raises SignatureError if invalid
"""
from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import nacl.encoding
import nacl.exceptions
import nacl.signing
import oqs


class SignatureError(Exception):
    """Raised when signature verification fails."""


@dataclasses.dataclass(frozen=True)
class DualSignature:
    """
    A pair of signatures over the same data.
    Both must be present and valid for the entry to be accepted.
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
    def from_dict(cls, d: dict[str, str]) -> "DualSignature":
        """Deserialize from hex strings."""
        return cls(
            ed25519_sig=bytes.fromhex(d["ed25519_sig"]),
            mldsa65_sig=bytes.fromhex(d["mldsa65_sig"]),
            ed25519_pub=bytes.fromhex(d["ed25519_pub"]),
            mldsa65_pub=bytes.fromhex(d["mldsa65_pub"]),
        )


class DualSigner:
    """
    Signs data with both Ed25519 (PyNaCl) and ML-DSA-65 (liboqs-python).

    Keys are persisted to a state directory. If no keys exist, call generate().
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

    @classmethod
    def generate(cls) -> "DualSigner":
        """Generate a fresh dual keypair. Keys are not persisted automatically."""
        ed25519_sk = nacl.signing.SigningKey.generate()
        with oqs.Signature(cls._MLDSA65_ALG) as signer:
            mldsa65_pk = signer.generate_keypair()
            mldsa65_sk = signer.export_secret_key()
        return cls(ed25519_sk, mldsa65_sk, mldsa65_pk)

    @classmethod
    def load(cls, state_dir: Path) -> "DualSigner":
        """Load keypair from state directory. Raises FileNotFoundError if absent."""
        ed25519_key_bytes = (state_dir / cls._ED25519_KEYFILE).read_bytes()
        ed25519_sk = nacl.signing.SigningKey(ed25519_key_bytes)

        mldsa65_sk = (state_dir / cls._MLDSA65_SK_FILE).read_bytes()
        mldsa65_pk = (state_dir / cls._MLDSA65_PK_FILE).read_bytes()

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
        """Sign data with both algorithms. Returns DualSignature."""
        # Ed25519 via PyNaCl
        signed = self._ed25519_sk.sign(data)
        ed25519_sig = bytes(signed.signature)  # first 64 bytes

        # ML-DSA-65 via liboqs
        with oqs.Signature(self._MLDSA65_ALG, self._mldsa65_sk) as signer:
            mldsa65_sig = signer.sign(data)

        return DualSignature(
            ed25519_sig=ed25519_sig,
            mldsa65_sig=mldsa65_sig,
            ed25519_pub=self.ed25519_public_key,
            mldsa65_pub=self.mldsa65_public_key,
        )

    @staticmethod
    def verify(data: bytes, dual_sig: DualSignature) -> None:
        """
        Verify both signatures over data.
        Raises SignatureError if either signature is invalid.
        BOTH must be valid — this is not an OR check.
        """
        # Verify Ed25519
        try:
            verify_key = nacl.signing.VerifyKey(dual_sig.ed25519_pub)
            verify_key.verify(data, dual_sig.ed25519_sig)
        except nacl.exceptions.BadSignatureError as exc:
            raise SignatureError(f"Ed25519 signature invalid: {exc}") from exc

        # Verify ML-DSA-65
        with oqs.Signature("ML-DSA-65") as verifier:
            ok = verifier.verify(data, dual_sig.mldsa65_sig, dual_sig.mldsa65_pub)
        if not ok:
            raise SignatureError("ML-DSA-65 signature invalid")
