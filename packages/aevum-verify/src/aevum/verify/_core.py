# SPDX-License-Identifier: Apache-2.0
"""
aevum.verify._core — standalone sigchain verifier.

Trust model
-----------
Classical anchor:  The pinned Ed25519 public-key bytes supplied out-of-band
                   (``ed25519_pub`` kwarg).  Every entry's Ed25519 signature is
                   verified against this key.

                   ``signer_key_id`` is an informational signed field whose
                   integrity is already guaranteed by the Ed25519 signature —
                   it lives inside the signing_fields set, so mutating it
                   invalidates the signature.  No identity comparison between
                   ``signer_key_id`` and the Ed25519 public key is performed;
                   the trust anchor is the key bytes, not the identifier.

Hybrid anchor:     The pinned Ed25519 key (above) PLUS the pinned ML-DSA-65
                   public-key bytes supplied out-of-band (``mldsa65_pub`` kwarg).
                   For hybrid entries (key_scheme ``ed25519+ml-dsa-65``):
                     - the embedded ``mldsa65_pub`` field must equal the pinned key;
                     - the ML-DSA-65 signature must verify against it.
                   Absence of either sig or pub → fail closed (tamper / downgrade).

Merkle + STH layer:
                   verify_inclusion / verify_consistency / leaf_hash / node_hash /
                   recompute_root are re-implemented from the RFC 6962 spec (SHA3-256).
                   They do NOT import from aevum.core.audit.merkle — independence is
                   enforced by the AST import test in test_merkle_sth.py.

                   verify_sth checks the hybrid STH signatures (Ed25519 + ML-DSA-65)
                   against PINNED keys using the same domain prefix and fail-closed
                   rules as entry verification.  An optional expected_root check
                   confirms the STH root matches the locally recomputed Merkle root.

                   verify_sth_tsa_full extends verify_sth_tsa (imprint-only) with
                   full RFC 3161 token-signature + cert-chain validation against a
                   pinned TSA root certificate.  Returns None / True / False
                   (no-token / valid / invalid) preserving the existing tri-state.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Protocol

import rfc8785
from aevum.core.audit.event import AuditEvent, _message_representative
from aevum.core.audit.sigchain import GENESIS_HASH
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from rfc3161_client import VerificationError, VerifierBuilder, decode_timestamp_response

logger = logging.getLogger(__name__)

# Maps the lower-case key_scheme suffix to the OQS algorithm name.
_MLDSA_LEVEL_MAP: dict[str, str] = {"ml-dsa-65": "ML-DSA-65"}

# ---------------------------------------------------------------------------
# Merkle constants (must match aevum.core.audit.merkle exactly)
# ---------------------------------------------------------------------------

# RFC 6962 leaf / node domain bytes
_LEAF: bytes = b"\x00"
_NODE: bytes = b"\x01"

# Empty-tree root: sha3_256(b"") — MTH of 0 entries per RFC 6962
EMPTY_ROOT: bytes = hashlib.sha3_256(b"").digest()

# STH domain prefix — cross-type separation from entry prefix b"aevum-sigchain-v1\x00"
_STH_DOMAIN: bytes = b"aevum-sth-v1\x00"

# SHA OID → hashlib algorithm (covers OIDs rfc3161-client uses for TSA imprints)
_SHA_OID_TO_ALGO: dict[str, str] = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


# ---------------------------------------------------------------------------
# _STHLike — duck-typed protocol satisfied by aevum.core.audit.merkle.SignedTreeHead
# (aevum.core.audit.merkle is never imported at runtime; independence enforced by test)
# ---------------------------------------------------------------------------

class _STHLike(Protocol):
    """Protocol satisfied by SignedTreeHead — used for type annotations only."""

    tree_size: int
    root_hash: str      # hex (32 bytes = 64 chars)
    timestamp: int      # Unix seconds
    log_id: str         # Ed25519 public key hex
    hash_alg: str       # "sha3-256"
    key_scheme: str     # "ed25519+ml-dsa-65"
    ed25519_sig: str    # url-safe base64
    mldsa65_sig: str    # hex
    mldsa65_pub: str    # hex
    ed25519_pub: str    # hex
    tsa_token: str | None


@dataclasses.dataclass(frozen=True)
class VerifyResult:
    """Result of a chain or entry verification.

    Attributes:
        ok:            True iff every verified entry is cryptographically intact.
        failing_index: 0-based index of the first failing entry (None when ok is True
                       or when the failure precedes entry iteration, e.g. homogeneity).
        reason:        Human-readable failure description (empty string when ok is True).
    """

    ok: bool
    failing_index: int | None = None
    reason: str = ""


def verify_entry(
    entry: AuditEvent,
    *,
    ed25519_pub: bytes,
    mldsa65_pub: bytes | None,
    expected_prior: str,
) -> VerifyResult:
    """Verify a single chain entry against pinned public keys.

    The check order matches aevum-core's verify_chain to guarantee that both
    implementations detect the same failure in the same entry.

    Args:
        entry:          The AuditEvent to verify.
        ed25519_pub:    Pinned Ed25519 public key bytes (32 bytes).
        mldsa65_pub:    Pinned ML-DSA-65 public key bytes; required for hybrid entries.
        expected_prior: Expected value of entry.prior_hash.

    Returns:
        VerifyResult(ok=True) if the entry is intact, VerifyResult(ok=False, ...) otherwise.
    """
    if entry.sig_format_version != 1:
        return VerifyResult(
            ok=False,
            reason=f"sig_format_version {entry.sig_format_version!r} != 1",
        )

    if entry.prior_hash != expected_prior:
        return VerifyResult(ok=False, reason="prior_hash mismatch")

    if AuditEvent.hash_payload(entry.payload) != entry.payload_hash:
        return VerifyResult(ok=False, reason="payload_hash mismatch")

    signing_fields: dict[str, Any] = {
        "event_id": entry.event_id,
        "episode_id": entry.episode_id,
        "sequence": entry.sequence,
        "event_type": entry.event_type,
        "schema_version": entry.schema_version,
        "valid_from": entry.valid_from,
        "valid_to": entry.valid_to,
        # HLC system_time may exceed 2^53; must be a string in the signed field set.
        "system_time": str(entry.system_time),
        "causation_id": entry.causation_id,
        "correlation_id": entry.correlation_id,
        "actor": entry.actor,
        "trace_id": entry.trace_id,
        "span_id": entry.span_id,
        "payload_hash": entry.payload_hash,
        "prior_hash": entry.prior_hash,
        "signer_key_id": entry.signer_key_id,
        "key_scheme": entry.key_scheme,
        "sig_format_version": 1,
        "hash_alg": entry.hash_alg,
    }
    representative = _message_representative(signing_fields)
    digest = hashlib.sha3_256(representative).digest()

    # Ed25519 verify against the PINNED key — the sole classical trust anchor.
    # No comparison of signer_key_id to the key bytes is performed here.
    try:
        public_key = Ed25519PublicKey.from_public_bytes(ed25519_pub)
        sig_bytes = base64.urlsafe_b64decode(entry.signature + "==")
        public_key.verify(sig_bytes, digest)
    except Exception:
        return VerifyResult(ok=False, reason="Ed25519 signature invalid")

    ks = entry.key_scheme
    if ks == "ed25519":
        pass  # classical-only; primary Ed25519 already verified
    elif ks.startswith("ed25519+"):
        level_suffix = ks[len("ed25519+"):]
        mldsa_alg = _MLDSA_LEVEL_MAP.get(level_suffix)
        if mldsa_alg is None:
            return VerifyResult(ok=False, reason=f"unknown ML-DSA level: {level_suffix!r}")

        # Fail closed: both sig and pub fields must be present for hybrid entries.
        if entry.mldsa65_sig is None or entry.mldsa65_pub is None:
            return VerifyResult(ok=False, reason="ML-DSA sig/pub absent for hybrid entry")

        # Caller must supply the pinned ML-DSA key for hybrid verification.
        if mldsa65_pub is None:
            return VerifyResult(
                ok=False,
                reason="hybrid entry requires --mldsa65-pub; no pinned ML-DSA-65 key supplied",
            )

        # Pinned-key match: the embedded key must equal the published anchor.
        if bytes.fromhex(entry.mldsa65_pub) != mldsa65_pub:
            return VerifyResult(
                ok=False,
                reason="embedded mldsa65_pub does not match pinned ML-DSA-65 key",
            )

        # ML-DSA verification over the representative bytes (not the hash of them).
        try:
            from aevum.core.signing import DualSigner

            DualSigner.verify_mldsa(
                representative,
                bytes.fromhex(entry.mldsa65_sig),
                mldsa65_pub,
                alg=mldsa_alg,
            )
        except Exception as exc:
            return VerifyResult(ok=False, reason=f"ML-DSA signature invalid: {exc}")
    else:
        return VerifyResult(ok=False, reason=f"unknown key_scheme: {ks!r}")

    return VerifyResult(ok=True)


def verify_chain(
    entries: list[AuditEvent],
    *,
    ed25519_pub: bytes,
    mldsa65_pub: bytes | None = None,
) -> VerifyResult:
    """Verify an entire sigchain from genesis.

    Applies the same pre-pass checks as aevum-core's Sigchain.verify_chain to
    guarantee both implementations detect failures at the same entry:
      1. sig_format_version == 1 for every entry.
      2. key_scheme homogeneity — a mixed chain is a downgrade/splice fingerprint.
      3. Per-entry: prior_hash linkage, payload_hash, Ed25519 + ML-DSA (if hybrid).

    Args:
        entries:     Ordered list of AuditEvent objects starting from genesis.
        ed25519_pub: Pinned Ed25519 public key bytes (the sole classical trust anchor).
        mldsa65_pub: Pinned ML-DSA-65 public key bytes; required for hybrid chains.

    Returns:
        VerifyResult(ok=True) if every entry is intact.
        VerifyResult(ok=False, failing_index=N, reason=...) on the first failure.
    """
    if not entries:
        return VerifyResult(ok=True)

    # Pre-pass 1: sig_format_version must be 1 for every entry.
    for i, e in enumerate(entries):
        if getattr(e, "sig_format_version", None) != 1:
            return VerifyResult(
                ok=False,
                failing_index=i,
                reason=f"sig_format_version {e.sig_format_version!r} != 1",
            )

    # Pre-pass 2: homogeneity — all entries must share the same key_scheme.
    # A mixed chain is the fingerprint of a downgrade or splice attack.
    schemes = {e.key_scheme for e in entries}
    if len(schemes) > 1:
        return VerifyResult(
            ok=False,
            reason=f"mixed key_scheme detected {schemes!r} — downgrade or splice attack",
        )

    expected_prior = GENESIS_HASH
    for i, entry in enumerate(entries):
        result = verify_entry(
            entry,
            ed25519_pub=ed25519_pub,
            mldsa65_pub=mldsa65_pub,
            expected_prior=expected_prior,
        )
        if not result.ok:
            return VerifyResult(ok=False, failing_index=i, reason=result.reason)
        expected_prior = AuditEvent.hash_event_for_chain(entry)

    return VerifyResult(ok=True)


# ---------------------------------------------------------------------------
# JSON serialization helpers (for CLI and test fixtures)
# ---------------------------------------------------------------------------

def event_to_dict(event: AuditEvent) -> dict[str, Any]:
    """Serialize an AuditEvent to a JSON-safe dict (receipt_cbor excluded)."""
    return {
        "event_id": event.event_id,
        "episode_id": event.episode_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
        "system_time": event.system_time,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "actor": event.actor,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "payload": event.payload,
        "payload_hash": event.payload_hash,
        "prior_hash": event.prior_hash,
        "signature": event.signature,
        "signer_key_id": event.signer_key_id,
        "mldsa65_sig": event.mldsa65_sig,
        "mldsa65_pub": event.mldsa65_pub,
        "tsa_url": event.tsa_url,
        "tsa_token": event.tsa_token,
        "key_scheme": event.key_scheme,
        "sig_format_version": event.sig_format_version,
        "hash_alg": event.hash_alg,
    }


def event_from_dict(d: dict[str, Any]) -> AuditEvent:
    """Deserialize an AuditEvent from a dict produced by event_to_dict."""
    return AuditEvent(
        event_id=d["event_id"],
        episode_id=d["episode_id"],
        sequence=int(d["sequence"]),
        event_type=d["event_type"],
        schema_version=d["schema_version"],
        valid_from=d["valid_from"],
        valid_to=d.get("valid_to"),
        system_time=int(d["system_time"]),
        causation_id=d.get("causation_id"),
        correlation_id=d.get("correlation_id"),
        actor=d["actor"],
        trace_id=d.get("trace_id"),
        span_id=d.get("span_id"),
        payload=d["payload"],
        payload_hash=d["payload_hash"],
        prior_hash=d["prior_hash"],
        signature=d["signature"],
        signer_key_id=d["signer_key_id"],
        mldsa65_sig=d.get("mldsa65_sig"),
        mldsa65_pub=d.get("mldsa65_pub"),
        tsa_url=d.get("tsa_url"),
        tsa_token=d.get("tsa_token"),
        key_scheme=d.get("key_scheme", "ed25519"),
        sig_format_version=d.get("sig_format_version"),
        hash_alg=d.get("hash_alg", "sha3-256"),
    )


def load_chain(path: Path) -> list[AuditEvent]:
    """Load a chain from a JSON file (array of event dicts)."""
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError(f"chain file must contain a JSON array, got {type(data).__name__}")
    return [event_from_dict(entry) for entry in data]


def dump_chain(events: list[AuditEvent], path: Path) -> None:
    """Write a chain to a JSON file."""
    path.write_text(json.dumps([event_to_dict(e) for e in events], indent=2))


# ---------------------------------------------------------------------------
# Merkle primitives — re-implemented from RFC 6962 spec (SHA3-256)
# Never imports from aevum.core.audit.merkle (independence enforced by AST test)
# ---------------------------------------------------------------------------

def leaf_hash(entry_digest: bytes) -> bytes:
    """sha3_256(0x00 || entry_digest) — RFC 6962 leaf hash with SHA3-256."""
    return hashlib.sha3_256(_LEAF + entry_digest).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """sha3_256(0x01 || left || right) — RFC 6962 internal node hash with SHA3-256."""
    return hashlib.sha3_256(_NODE + left + right).digest()


def _mth_impl(nodes: list[bytes]) -> bytes:
    n = len(nodes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return nodes[0]
    k = 1 << ((n - 1).bit_length() - 1)  # largest power of two < n
    return node_hash(_mth_impl(nodes[:k]), _mth_impl(nodes[k:]))


def recompute_root(entries: list[AuditEvent]) -> bytes:
    """Recompute the Merkle root from AuditEvent entries.

    Leaf input per entry: bytes.fromhex(AuditEvent.hash_event_for_chain(entry)).
    This matches aevum-core's MerkleLog.signed_tree_head() leaf-digest definition.
    Empty list → EMPTY_ROOT.
    """
    leaves = [leaf_hash(bytes.fromhex(AuditEvent.hash_event_for_chain(e))) for e in entries]
    return _mth_impl(leaves)


def verify_inclusion(
    leaf_hash_value: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """RFC 6962 §2.1.1 inclusion verifier (re-implemented, independent of aevum-core).

    Returns True iff the inclusion proof for leaf_hash_value at index in a tree of
    tree_size entries recomputes to root.  Never calls aevum.core.audit.merkle.
    """
    if index >= tree_size:
        return False
    fn = index
    sn = tree_size - 1
    r = leaf_hash_value
    for step in proof:
        if fn & 1 or fn == sn:
            r = node_hash(step, r)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, step)
        fn >>= 1
        sn >>= 1
    return r == root and sn == 0


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """RFC 6962 §2.1.2 consistency verifier (re-implemented, independent of aevum-core).

    Returns True iff the log only grew (no history rewritten) between old and new.
    m==0 → True; m==n → True iff roots equal and proof empty; m>n → False.
    Never calls aevum.core.audit.merkle.
    """
    if old_size > new_size:
        return False
    if old_size == 0:
        return True
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0

    fn = old_size - 1
    sn = new_size - 1

    while fn & 1:
        fn >>= 1
        sn >>= 1

    proof_iter = iter(proof)

    if fn == 0:
        fr = old_root
        sr = old_root
    else:
        first = next(proof_iter, None)
        if first is None:
            return False
        fr = first
        sr = first

    for c in proof_iter:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return False
    return fr == old_root and sr == new_root


# ---------------------------------------------------------------------------
# STH field canonicalization (mirrors _sth_fields in aevum-core merkle.py)
# ---------------------------------------------------------------------------

def _sth_canonical_fields(sth: _STHLike) -> dict[str, Any]:
    return {
        "hash_alg": sth.hash_alg,
        "key_scheme": sth.key_scheme,
        "log_id": sth.log_id,
        "root_hash": sth.root_hash,
        # tree_size and timestamp encoded as strings (may exceed 2^53 in long-lived logs)
        "timestamp": str(sth.timestamp),
        "tree_size": str(sth.tree_size),
    }


# ---------------------------------------------------------------------------
# STH signature verifier
# ---------------------------------------------------------------------------

def verify_sth(
    sth: _STHLike,
    *,
    ed25519_pub: bytes,
    mldsa65_pub: bytes | None = None,
    expected_root: bytes | None = None,
) -> bool:
    """Verify hybrid STH signatures against PINNED keys. Fail-closed: both must pass.

    Reconstructs STH_DOMAIN + rfc8785(fields) and verifies:
      - Ed25519 over sha3_256(representative) using the PINNED ed25519_pub
      - ML-DSA-65 over representative directly using the PINNED mldsa65_pub

    If expected_root is provided (typically from recompute_root(entries)) the
    check also fails if bytes.fromhex(sth.root_hash) != expected_root.

    Returns False if either signature is invalid, if mldsa65_pub is absent, or
    if the expected_root check fails.  Never raises — always returns bool.
    """
    if expected_root is not None and bytes.fromhex(sth.root_hash) != expected_root:
        return False

    fields = _sth_canonical_fields(sth)
    representative: bytes = _STH_DOMAIN + rfc8785.dumps(fields)
    digest = hashlib.sha3_256(representative).digest()

    # Ed25519 over sha3_256(representative)
    try:
        sig_bytes = base64.urlsafe_b64decode(sth.ed25519_sig + "==")
        pub = Ed25519PublicKey.from_public_bytes(ed25519_pub)
        pub.verify(sig_bytes, digest)
    except Exception:
        return False

    # ML-DSA-65 over representative directly (fail-closed: required for hybrid STH)
    if mldsa65_pub is None:
        return False
    try:
        from aevum.core.signing import DualSigner
        DualSigner.verify_mldsa(
            representative,
            bytes.fromhex(sth.mldsa65_sig),
            mldsa65_pub,
        )
    except Exception:
        return False

    return True


# ---------------------------------------------------------------------------
# TSA full chain verifier
# ---------------------------------------------------------------------------

def verify_sth_tsa_full(
    sth: _STHLike,
    *,
    tsa_root_cert: bytes,
) -> bool | None:
    """Full RFC 3161 TSA validation: imprint + token signature + chain to pinned root.

    Extends the imprint-only check in aevum-core's verify_sth_tsa with:
      (ii)  token signature verified via PKCS#7 chain
      (iii) signing cert chains to the PINNED tsa_root_cert (PEM or DER bytes)
            — the token's own embedded chain is verified *against* this anchor,
              never trusted in isolation.

    Returns:
        None   — sth.tsa_token is absent (no attestation; not invalid).
        True   — imprint == root hash AND token signature valid AND chain to root.
        False  — token present but any check fails.
    """
    if sth.tsa_token is None:
        return None
    try:
        token_bytes = bytes.fromhex(sth.tsa_token)
        response = decode_timestamp_response(token_bytes)
        root_bytes = bytes.fromhex(sth.root_hash)

        # Load the pinned root cert (accept PEM or DER)
        try:
            root_cert = load_pem_x509_certificate(tsa_root_cert)
        except Exception:
            root_cert = load_der_x509_certificate(tsa_root_cert)

        # Build the verifier anchored to the pinned root.
        # If the token has no embedded signing cert, also supply the root cert as the
        # explicit leaf (self-signed root-is-signer case). For tokens with embedded
        # certs the VerifierBuilder uses them for chain building.
        has_embedded_certs = len(response.signed_data.certificates) > 0
        builder = VerifierBuilder().add_root_certificate(root_cert)
        if not has_embedded_certs:
            builder = builder.tsa_certificate(root_cert)
        verifier = builder.build()

        # verify_message: hashes root_bytes with the token's own algorithm,
        # then verifies imprint match + PKCS#7 chain + EKU (id-kp-timeStamping)
        verifier.verify_message(response, root_bytes)
        return True
    except (VerificationError, Exception) as exc:
        logger.debug("TSA full validation failed: %s", exc)
        return False
