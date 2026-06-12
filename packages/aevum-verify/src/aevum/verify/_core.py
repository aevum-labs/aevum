# SPDX-License-Identifier: Apache-2.0
"""
Standalone independent verifier — re-implements Aevum sigchain verification from spec.

INDEPENDENCE GUARANTEE: this module imports only stdlib + cryptography + rfc8785 + oqs.
It deliberately does NOT import aevum.core.audit.sigchain or any other aevum-core module.
The conformance cross-check test (test_p2j_verify.py) enforces this structurally.

TRUST ANCHOR MODEL:
  The caller provides the published public key(s) out-of-band — the trust anchor.
  For each entry:
    Ed25519 — verify signature against the PINNED key; check signer_key_id equals pinned key id.
    ML-DSA  — check entry's mldsa65_pub EQUALS the pinned key (mismatch → FAIL, forgery attempt);
               then verify mldsa65_sig over the representative with the level from key_scheme.

SIGNING REPRESENTATIVE (compute-once property, Spec Section 06):
  representative = DOMAIN_PREFIX + rfc8785.dumps(19 signing fields)
  Ed25519 signed digest = sha3_256(representative)
  ML-DSA input          = representative   (not its hash)
  chain hash            = sha3_256(representative).hexdigest()

All three derive from the same bytes — altering any signed field breaks all three proofs.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ── Spec constants ────────────────────────────────────────────────────────────

DOMAIN_PREFIX: bytes = b"aevum-sigchain-v1\x00"

# sha3_256(b"aevum:genesis") — the expected prior_hash of the very first chain entry.
# Deterministic constant: any independent validator can reproduce this without trusting
# the operator's stored state.
GENESIS_HASH: str = hashlib.sha3_256(b"aevum:genesis").hexdigest()

_JSON_SAFE_INT_MAX = 2**53 - 1  # RFC 8785 §3.2.2.3

# ML-DSA level suffix (from key_scheme) → OQS algorithm name.
_MLDSA_LEVEL_MAP: dict[str, str] = {"ml-dsa-65": "ML-DSA-65"}


# ── Result type ───────────────────────────────────────────────────────────────

@dataclasses.dataclass
class VerifyResult:
    """Result of a verification operation."""

    ok: bool
    message: str
    verified_count: int = 0
    failed_index: int | None = None
    failed_reason: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"VERIFIED ({self.verified_count} {'entry' if self.verified_count == 1 else 'entries'})"
        return f"FAILED at entry {self.failed_index}: {self.failed_reason}"


# ── Canonical byte construction ───────────────────────────────────────────────

def _canonicalize(fields: dict[str, Any]) -> bytes:
    """RFC 8785-canonicalize fields. Rejects floats and unsafe integers."""
    for k, v in fields.items():
        if isinstance(v, float):
            raise ValueError(f"float in signed field {k!r} is forbidden")
        if isinstance(v, int) and not isinstance(v, bool) and abs(v) > _JSON_SAFE_INT_MAX:
            raise ValueError(f"integer in {k!r} exceeds RFC 8785 safe domain; convert to str")
    return rfc8785.dumps(fields)


def _representative(fields: dict[str, Any]) -> bytes:
    """Produce the canonical byte string: DOMAIN_PREFIX + RFC-8785-canonical-JSON(fields).

    This is the single linchpin function — Ed25519 signed digest, ML-DSA input, and chain
    hash all derive from sha3_256(representative) or representative itself.
    """
    return DOMAIN_PREFIX + _canonicalize(fields)


def _build_signing_fields(entry: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the 19 signing fields from an entry dict.

    Matches the field order and encoding used by aevum-core's new_event() and
    hash_event_for_chain(). Critically: sig_format_version is always hardcoded to 1,
    never read from the entry (the signer hardcodes it the same way).
    """
    return {
        "event_id": entry["event_id"],
        "episode_id": entry["episode_id"],
        "sequence": entry["sequence"],
        "event_type": entry["event_type"],
        "schema_version": entry["schema_version"],
        "valid_from": entry["valid_from"],
        "valid_to": entry["valid_to"],
        # system_time is a HLC integer (may exceed 2^53); signer encodes as str for RFC 8785.
        "system_time": str(entry["system_time"]),
        "causation_id": entry["causation_id"],
        "correlation_id": entry["correlation_id"],
        "actor": entry["actor"],
        "trace_id": entry["trace_id"],
        "span_id": entry["span_id"],
        "payload_hash": entry["payload_hash"],
        "prior_hash": entry["prior_hash"],
        "signer_key_id": entry["signer_key_id"],
        "key_scheme": entry["key_scheme"],
        "sig_format_version": 1,  # always 1 — never read from entry
        "hash_alg": entry["hash_alg"],
    }


def _chain_hash(entry: dict[str, Any]) -> str:
    """Compute sha3_256(representative).hexdigest() for an entry — stored as prior_hash in successor."""
    fields = _build_signing_fields(entry)
    return hashlib.sha3_256(_representative(fields)).hexdigest()


def _payload_hash(payload: dict[str, Any] | None) -> str:
    """SHA3-256 of the canonical payload bytes."""
    canonical = json.dumps(payload or {}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_256(canonical).hexdigest()


# ── ML-DSA verification ───────────────────────────────────────────────────────

def _verify_mldsa(data: bytes, sig: bytes, pub: bytes, *, alg: str) -> None:
    """Verify an ML-DSA signature over data. Raises on invalid sig or missing liboqs.

    Uses liboqs-python (oqs). The caller must have the [pqc] extra installed.
    """
    try:
        import oqs
    except (ImportError, OSError, RuntimeError) as exc:
        raise RuntimeError(
            "liboqs (ML-DSA) required for hybrid verification but not available. "
            "Install: pip install 'aevum-verify[pqc]'"
        ) from exc
    with oqs.Signature(alg) as verifier:
        ok = verifier.verify(data, sig, pub)
    if not ok:
        raise ValueError(f"{alg} signature invalid")


# ── Per-entry signature verification ─────────────────────────────────────────

def _check_entry_sigs(
    entry: dict[str, Any],
    *,
    ed25519_pub: bytes,
    mldsa_pub: bytes | None,
) -> str | None:
    """Verify all signatures on one entry against pinned keys. Returns None on success, error str on failure.

    Trust anchor enforcement is the core of this function:
      Ed25519 — verify against pinned ed25519_pub; signer_key_id must equal pinned key's hex id.
      ML-DSA  — entry's mldsa65_pub MUST equal pinned mldsa_pub byte-for-byte (any mismatch
                is a forgery attempt — fail immediately without verifying the signature).
    """
    # --- signer_key_id trust anchor: must match hex of pinned Ed25519 key ---
    # In aevum-core, key_id is always bytes(signing_key.verify_key).hex() — the raw key hex.
    pinned_key_id = ed25519_pub.hex()
    if entry.get("signer_key_id") != pinned_key_id:
        return (
            f"signer_key_id {entry.get('signer_key_id')!r} does not match "
            f"pinned Ed25519 key id {pinned_key_id!r}"
        )

    # --- Reconstruct representative (same bytes the signer used) ---
    fields = _build_signing_fields(entry)
    rep = _representative(fields)
    digest = hashlib.sha3_256(rep).digest()

    # --- Ed25519 signature verification against PINNED key ---
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(ed25519_pub)
        raw_sig = base64.urlsafe_b64decode(entry["signature"] + "==")
        pub_key.verify(raw_sig, digest)
    except Exception as exc:
        return f"Ed25519 signature invalid: {exc}"

    # --- Payload hash integrity ---
    if _payload_hash(entry.get("payload")) != entry.get("payload_hash"):
        return "payload_hash mismatch (payload was tampered)"

    # --- key_scheme dispatch ---
    ks = entry.get("key_scheme", "ed25519")
    if ks == "ed25519":
        pass  # classical-only: Ed25519 already verified above

    elif ks.startswith("ed25519+"):
        level_suffix = ks[len("ed25519+"):]
        mldsa_alg = _MLDSA_LEVEL_MAP.get(level_suffix)
        if mldsa_alg is None:
            return f"unknown ML-DSA level suffix {level_suffix!r} in key_scheme — fail closed"

        # Fail-closed: both mldsa fields are required on hybrid entries.
        if not entry.get("mldsa65_sig") or not entry.get("mldsa65_pub"):
            return "hybrid entry (key_scheme starts with 'ed25519+') missing mldsa65_sig or mldsa65_pub — fail closed"

        # Pinned ML-DSA key required from the caller.
        if mldsa_pub is None:
            return "hybrid chain requires a pinned ML-DSA public key (--mldsa-pubkey)"

        # TRUST ANCHOR: entry's mldsa65_pub must equal the pinned key byte-for-byte.
        # An entry carrying a different key is a forgery attempt — reject before verifying.
        if entry["mldsa65_pub"] != mldsa_pub.hex():
            return (
                "mldsa65_pub in entry differs from pinned ML-DSA key — "
                "forgery attempt or key mismatch: reject"
            )

        # Verify ML-DSA over the representative (not its hash — ML-DSA signs the full bytes).
        try:
            _verify_mldsa(rep, bytes.fromhex(entry["mldsa65_sig"]), mldsa_pub, alg=mldsa_alg)
        except Exception as exc:
            return f"ML-DSA-65 signature invalid: {exc}"

    else:
        return f"unknown key_scheme {ks!r} — fail closed"

    return None  # all checks passed


# ── Public API ────────────────────────────────────────────────────────────────

def verify_entry(
    entry: dict[str, Any],
    *,
    ed25519_pub: bytes,
    mldsa_pub: bytes | None = None,
) -> VerifyResult:
    """Verify a single sigchain entry against pinned public keys.

    Args:
        entry:       Dict representation of an AuditEvent (as from dataclasses.asdict()).
        ed25519_pub: Pinned Ed25519 public key bytes (32 bytes, raw). Trust anchor — must
                     be obtained out-of-band, never from the entry itself.
        mldsa_pub:   Pinned ML-DSA-65 public key bytes. Required when key_scheme is hybrid.

    Returns:
        VerifyResult with ok=True if all checks pass, False otherwise.
    """
    if entry.get("sig_format_version") != 1:
        return VerifyResult(
            ok=False, message="FAILED", failed_index=0,
            failed_reason=f"sig_format_version must be 1, got {entry.get('sig_format_version')!r}",
        )

    err = _check_entry_sigs(entry, ed25519_pub=ed25519_pub, mldsa_pub=mldsa_pub)
    if err:
        return VerifyResult(ok=False, message="FAILED", failed_index=0, failed_reason=err)
    return VerifyResult(ok=True, message="VERIFIED", verified_count=1)


def verify_chain(
    entries: list[dict[str, Any]],
    *,
    ed25519_pub: bytes,
    mldsa_pub: bytes | None = None,
) -> VerifyResult:
    """Verify a complete sigchain from genesis.

    An entry is intact when ALL of the following hold:
      1. sig_format_version == 1 (pre-pass; None or any other value is rejected).
      2. All entries share the same key_scheme — homogeneity (mixed chain = downgrade/splice attack).
      3. prior_hash matches GENESIS_HASH for entry #1, or sha3_256(representative) of preceding entry.
      4. payload_hash == sha3_256(canonical_payload).
      5. Ed25519 signature verifies against the PINNED key (not the entry-embedded key).
      6. signer_key_id equals the pinned Ed25519 key's hex id.
      7. For hybrid entries: mldsa65_pub in the entry EQUALS the pinned mldsa_pub (byte-for-byte);
         mldsa65_sig verifies against the representative; missing sig/pub → FAIL (fail-closed).

    Returns VERIFIED(n) or FAILED(index, reason) — stops at first failure.

    Args:
        entries:     Ordered list of entry dicts, as from [dataclasses.asdict(e) for e in events].
        ed25519_pub: Pinned Ed25519 public key bytes (trust anchor, out-of-band).
        mldsa_pub:   Pinned ML-DSA-65 public key bytes (required for hybrid chains).
    """
    if not entries:
        return VerifyResult(ok=True, message="VERIFIED", verified_count=0)

    # Pre-pass 1: sig_format_version — every entry must be 1. No fallback, no legacy path.
    for i, e in enumerate(entries):
        if e.get("sig_format_version") != 1:
            return VerifyResult(
                ok=False, message="FAILED", verified_count=i, failed_index=i,
                failed_reason=f"sig_format_version must be 1, got {e.get('sig_format_version')!r}",
            )

    # Pre-pass 2: homogeneity — all entries must share the same key_scheme.
    # Mixed key_scheme is the fingerprint of a downgrade or splice attack.
    schemes = {e.get("key_scheme", "ed25519") for e in entries}
    if len(schemes) > 1:
        return VerifyResult(
            ok=False, message="FAILED", verified_count=0, failed_index=0,
            failed_reason=f"mixed key_scheme in chain (downgrade/splice attack): {sorted(schemes)}",
        )

    expected_prior = GENESIS_HASH
    for i, entry in enumerate(entries):
        # Chain linkage: prior_hash must match expected value.
        if entry.get("prior_hash") != expected_prior:
            return VerifyResult(
                ok=False, message="FAILED", verified_count=i, failed_index=i,
                failed_reason=(
                    f"prior_hash mismatch at index {i}: "
                    f"expected {expected_prior!r}, got {entry.get('prior_hash')!r}"
                ),
            )

        # Per-entry signature + trust-anchor verification.
        err = _check_entry_sigs(entry, ed25519_pub=ed25519_pub, mldsa_pub=mldsa_pub)
        if err:
            return VerifyResult(
                ok=False, message="FAILED", verified_count=i, failed_index=i,
                failed_reason=err,
            )

        # Advance the expected prior hash for the next entry (compute-once property).
        expected_prior = _chain_hash(entry)

    return VerifyResult(ok=True, message="VERIFIED", verified_count=len(entries))
