# SPDX-License-Identifier: Apache-2.0
"""
AuditEvent — the canonical episodic ledger entry format. Spec Section 06.2.

Every entry written to the sigchain is an AuditEvent. It is immutable (frozen dataclass),
cryptographically signed, and chained to its predecessor via prior_hash. The 19 core fields
(18 original + hash_alg added in P2g) are always present; the optional Phase 1 fields carry
dual-sig and TSA data and are nullable on pre-Phase-1 entries.

An investigator reading a serialised AuditEvent can determine, without trusting the operator:
  WHO caused the event   (actor, signer_key_id)
  WHAT happened          (event_type, payload, payload_hash)
  WHEN                   (valid_from, system_time)
  WHERE in the chain     (sequence, prior_hash)
  PROOF of integrity     (signature + hash_event_for_chain linkage)
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from collections.abc import Mapping
from typing import Any

import rfc8785

# Byte-level domain separator bound into every signed representative (P2g).
# Binds the protocol name and wire-format version into the signed bytes even for
# contexts that parse the JSON differently. \x00 separates the ASCII prefix from
# the RFC 8785 JSON body so there is no ambiguity about the boundary.
# sig_format_version handles field-set evolution; this prefix handles protocol/wire-format domain.
DOMAIN_PREFIX: bytes = b"aevum-sigchain-v1\x00"


_JSON_SAFE_INT_MAX = 2**53 - 1  # RFC 8785 §3.2.2.3: integers outside this range are not safe


def _canonicalize(fields: Mapping[str, Any]) -> bytes:
    """RFC 8785-canonicalize a dict to bytes.

    Floats are forbidden (non-deterministic representation across platforms).
    Integers must be within the safe JSON integer domain ([-2^53+1, 2^53-1]).
    HLC system_time values exceed 2^53 — callers must convert them to strings first.
    """
    for k, v in fields.items():
        if isinstance(v, float):
            raise ValueError(f"float in signed field {k!r} is forbidden (use int or str)")
        if isinstance(v, int) and not isinstance(v, bool) and abs(v) > _JSON_SAFE_INT_MAX:
            raise ValueError(
                f"integer in signed field {k!r} ({v}) exceeds RFC 8785 safe domain "
                f"(2^53-1); convert to str before signing"
            )
    return rfc8785.dumps(fields)


def _message_representative(fields: Mapping[str, Any]) -> bytes:
    """Produce the canonical byte string that ALL signing and hashing operations are applied to.

    Returns DOMAIN_PREFIX + RFC-8785-canonical-JSON(fields).
    This single function is the linchpin of the compute-once property:
      - Ed25519 signed digest = sha3_256(_message_representative(19 fields))
      - ML-DSA input          = _message_representative(19 fields)
      - chain hash            = sha3_256(_message_representative(19 fields)).hexdigest()
    All three are derived from the same bytes, so altering any signed field breaks all
    three proofs simultaneously.
    """
    return DOMAIN_PREFIX + _canonicalize(fields)


def _build_signing_fields(
    *,
    event_id: str,
    episode_id: str,
    sequence: int,
    event_type: str,
    schema_version: str,
    valid_from: str,
    valid_to: str | None,
    system_time: int,
    causation_id: str | None,
    correlation_id: str | None,
    actor: str,
    trace_id: str | None,
    span_id: str | None,
    payload_hash: str,
    prior_hash: str,
    signer_key_id: str,
    key_scheme: str,
    sig_format_version: int,
    hash_alg: str,
    principal_binding: str | None = None,
    principal_commitment: str | None = None,
    principal_commitment_key_id: str | None = None,
) -> dict[str, Any]:
    """Build the signing_fields dict for a given sig_format_version (DD4 per-entry dispatch).

    sig_format_version == 1: exactly the 19 spec fields (unchanged since P2g).
    sig_format_version == 2: the same 19 fields plus principal_binding,
      principal_commitment, principal_commitment_key_id (DD2/DD3) — additive only,
      so a v1 verifier that has not been upgraded still rejects v2 entries outright
      (it never silently ignores the extra fields).

    Callers must have already validated sig_format_version is 1 or 2; this function
    does not validate it, it only dispatches on it.
    """
    fields: dict[str, Any] = {
        "event_id": event_id,
        "episode_id": episode_id,
        "sequence": sequence,
        "event_type": event_type,
        "schema_version": schema_version,
        "valid_from": valid_from,
        "valid_to": valid_to,
        # system_time is a HLC integer that may exceed 2^53; encode as string for RFC 8785.
        "system_time": str(system_time),
        "causation_id": causation_id,
        "correlation_id": correlation_id,
        "actor": actor,
        "trace_id": trace_id,
        "span_id": span_id,
        "payload_hash": payload_hash,
        "prior_hash": prior_hash,
        "signer_key_id": signer_key_id,
        "key_scheme": key_scheme,
        "sig_format_version": sig_format_version,
        "hash_alg": hash_alg,
    }
    if sig_format_version == 2:
        fields["principal_binding"] = principal_binding
        fields["principal_commitment"] = principal_commitment
        fields["principal_commitment_key_id"] = principal_commitment_key_id
    return fields


def signing_fields_from_event(event: AuditEvent) -> dict[str, Any]:
    """Build the signing_fields dict for an already-constructed AuditEvent.

    Dispatches on event.sig_format_version (DD4): v1 entries sign the 19 spec
    fields; v2 entries additionally sign the 3 principal-binding fields. Callers
    (hash_event_for_chain, Sigchain.verify_chain) must have already rejected any
    sig_format_version outside {1, 2} before calling this.
    """
    if event.sig_format_version is None:
        raise ValueError("sig_format_version must be set before signing")
    return _build_signing_fields(
        event_id=event.event_id,
        episode_id=event.episode_id,
        sequence=event.sequence,
        event_type=event.event_type,
        schema_version=event.schema_version,
        valid_from=event.valid_from,
        valid_to=event.valid_to,
        system_time=event.system_time,
        causation_id=event.causation_id,
        correlation_id=event.correlation_id,
        actor=event.actor,
        trace_id=event.trace_id,
        span_id=event.span_id,
        payload_hash=event.payload_hash,
        prior_hash=event.prior_hash,
        signer_key_id=event.signer_key_id,
        key_scheme=event.key_scheme,
        sig_format_version=event.sig_format_version,
        hash_alg=event.hash_alg,
        principal_binding=event.principal_binding,
        principal_commitment=event.principal_commitment,
        principal_commitment_key_id=event.principal_commitment_key_id,
    )


# DD7: allow-list of claims that may appear in a principal_binding blob. "sub" (the
# raw subject) and any bearer-token-shaped value are structurally excluded by being
# absent from this set — this is a deny-by-default extractor, not a redaction filter.
_PRINCIPAL_BINDING_ALLOWED_KEYS = frozenset({"iss", "aud", "jti", "iat", "exp", "cnf"})
# RFC 7800 'cnf' (confirmation claim) is restricted to its RFC 7638 JWK thumbprint
# ('jkt') — never the raw key or any other proof-of-possession material.
_CNF_ALLOWED_KEYS = frozenset({"jkt"})

# HO-G-PLUMB SR4: generous headroom for realistic OIDC sub / SPIFFE ID / DID values
# and claim sets (mirrors the size-bound posture aevum-verify applies to hex fields,
# MAX_HEX_FIELD_LEN — HO-C) — not a tight fit, but oversized input is rejected before
# any HMAC/canonicalization work to prevent a DoS via new_event().
MAX_PRINCIPAL_IDENTITY_LEN = 2_048
MAX_PRINCIPAL_CLAIMS_SERIALIZED_LEN = 16_384


def validate_principal_binding_sizes(
    principal_identity: str | None, principal_claims: Mapping[str, Any] | None
) -> None:
    """Reject oversized principal-binding inputs (SR4). Never includes the raw
    value in the raised message — only lengths — so a caller logging the
    exception cannot leak the identity or claims (SR2)."""
    if principal_identity is not None and len(principal_identity) > MAX_PRINCIPAL_IDENTITY_LEN:
        raise ValueError(
            f"principal_identity length {len(principal_identity)} exceeds "
            f"{MAX_PRINCIPAL_IDENTITY_LEN} limit"
        )
    if principal_claims is not None:
        serialized_len = len(json.dumps(principal_claims, default=str))
        if serialized_len > MAX_PRINCIPAL_CLAIMS_SERIALIZED_LEN:
            raise ValueError(
                f"principal_claims serialized length {serialized_len} exceeds "
                f"{MAX_PRINCIPAL_CLAIMS_SERIALIZED_LEN} limit"
            )


def build_principal_binding_blob(claims: Mapping[str, Any]) -> str:
    """Build the v2 principal_binding signed field from verified credential claims.

    DD7: the blob carries verifiable claims (iss/aud/jti/iat/exp) plus an RFC 7800
    'cnf' confirmation claim restricted to its RFC 7638 JWK thumbprint ('jkt'). Built
    by ALLOW-LIST extraction from `claims` — never a deny-list — so the raw subject
    ('sub') and any bearer-token-shaped value are structurally excluded regardless of
    what the caller passes in.

    Returns base64url (no padding) of the RFC 8785 canonical JSON of the extracted
    claims. Callers must pass already-verified claims (e.g. from a validated OIDC ID
    token) — this function does not verify a signature or check expiry.
    """
    extracted: dict[str, Any] = {
        k: claims[k] for k in _PRINCIPAL_BINDING_ALLOWED_KEYS if k in claims
    }
    if "cnf" in extracted and isinstance(extracted["cnf"], Mapping):
        extracted["cnf"] = {k: v for k, v in extracted["cnf"].items() if k in _CNF_ALLOWED_KEYS}
    canonical = _canonicalize(extracted)
    return base64.urlsafe_b64encode(canonical).rstrip(b"=").decode()


def compute_principal_commitment(commitment_key: bytes, principal_identity: str) -> str:
    """base64url (no padding) HMAC-SHA256(commitment_key, principal_identity) — DD1/DD6.

    The HMAC input is the bound CREDENTIAL identity (OIDC sub / SPIFFE ID / DID),
    never the plaintext actor field (DD1) — actor names a role or service account;
    principal_commitment names a specific verified external credential. The chain
    verifier never calls this function — the commitment is opaque signed bytes to it
    (DD6); only identity-matching (CommitmentKeyStore, with the key) calls it.
    """
    import hmac
    from hashlib import sha256

    digest = hmac.new(commitment_key, principal_identity.encode("utf-8"), sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    """Immutable episodic ledger entry. 19 signed fields (16 base + key_scheme +
    sig_format_version + hash_alg) plus optional Phase 1 dual-sig attachment fields
    (mldsa65_sig, mldsa65_pub, tsa_url, tsa_token, receipt_cbor).

    P2-IDENTITY-V2 (spec aevum-signing-v2.md): sig_format_version == 2 entries sign
    three additional NULLABLE fields — principal_binding, principal_commitment,
    principal_commitment_key_id — that bind the event to a verified external
    credential identity without exposing it in plaintext. See
    signing_fields_from_event() for the per-version field-set dispatch (DD4).

    Frozen so that field values cannot change after construction — hash_event_for_chain()
    must produce identical bytes every time for chain verification to hold.
    """

    # --- Identity fields ---
    # Uniquely identify the event, its episode group, its position in the chain sequence,
    # the type of event that occurred, and the schema version for forward-compat parsing.
    # episode_id groups related events into a logical session or workflow instance.
    event_id: str
    episode_id: str
    sequence: int
    event_type: str
    schema_version: str
    # --- Temporal / bi-temporal validity fields ---
    # valid_from / valid_to record the real-world validity window of the fact in payload.
    # valid_to is None for point-in-time facts with no scheduled expiry.
    # system_time is a Hybrid Logical Clock (HLC) integer (see aevum.core.audit.hlc) that
    # provides causal ordering across distributed nodes even when wall-clock time skews.
    valid_from: str
    valid_to: str | None
    system_time: int
    # --- Distributed tracing and causation fields ---
    # causation_id / correlation_id support event sourcing patterns: causation_id is the
    # ID of the event that directly caused this one; correlation_id groups all events in
    # a logical transaction. Both are optional for events with no upstream cause.
    # actor is the principal who triggered this event and is required (never empty) —
    # accountability is a hard invariant; an event without a responsible actor is invalid.
    # trace_id / span_id carry OpenTelemetry (OTEL) trace context for cross-system correlation.
    causation_id: str | None
    correlation_id: str | None
    actor: str
    trace_id: str | None
    span_id: str | None
    # --- Payload fields ---
    # payload is the application-specific data blob for this event. payload_hash is
    # SHA3-256(canonical_payload) stored separately so the payload can be verified
    # independently of the chain — an investigator can confirm the payload was not
    # tampered with by re-hashing, without needing to traverse the full chain.
    payload: dict[str, Any]
    payload_hash: str
    # --- Chain linkage field ---
    # prior_hash chains this entry to its predecessor (GENESIS_HASH for the very first entry).
    # Its value is SHA3-256(hash_event_for_chain(previous_event)). Any modification to a
    # preceding entry invalidates every subsequent prior_hash — tampering with one entry
    # makes the chain break at that point and all entries after it fail verification.
    prior_hash: str
    # --- Primary signing fields ---
    # signature is the url-safe base64 Ed25519 (RFC 8032) signature over SHA3-256(signing_fields).
    # signer_key_id identifies which key produced this signature — required for key rotation
    # so that historical entries can still be verified using the correct archived public key.
    signature: str
    signer_key_id: str
    # Phase 1: dual-sig fields (nullable — absent on classical entries)
    mldsa65_sig: str | None = None   # hex, ~6618 chars
    mldsa65_pub: str | None = None   # hex, ~3904 chars
    tsa_url: str | None = None
    tsa_token: str | None = None     # hex of DER bytes
    # Algorithm selector; "ed25519" (classical) | "ed25519+ml-dsa-65" (hybrid).
    key_scheme: str = "ed25519"
    # P2a: version marker for the signing_fields set.
    # Always 1 for entries produced by new_event; verify_chain rejects any entry where this
    # is not 1 (including None).
    sig_format_version: int | None = None
    # P2g: hash algorithm used for the signed digest and chain hash. Always "sha3-256".
    # Bound into the signed field set so that changing the hash algorithm changes the signature.
    hash_alg: str = "sha3-256"
    # Phase 1A: COSE_Sign1 receipt bytes (None when no encoder is configured).
    receipt_cbor: bytes | None = None
    # P2-IDENTITY-V2: principal-binding fields (DD2, spec aevum-signing-v2.md). Nullable
    # even on sig_format_version == 2 entries — null when an event has no external
    # credential to bind. Only signed (included in signing_fields) when
    # sig_format_version == 2; see signing_fields_from_event / _build_signing_fields.
    principal_binding: str | None = None
    principal_commitment: str | None = None
    principal_commitment_key_id: str | None = None

    def __post_init__(self) -> None:
        if not self.actor:
            raise ValueError("actor MUST NOT be empty")
        if self.sequence < 1:
            raise ValueError(f"sequence must be >= 1, got {self.sequence}")
        if not self.event_type:
            raise ValueError("event_type MUST NOT be empty")

    @staticmethod
    def canonical_payload(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def hash_payload(payload: dict[str, Any]) -> str:
        return hashlib.sha3_256(AuditEvent.canonical_payload(payload)).hexdigest()

    @staticmethod
    def hash_event_for_chain(event: AuditEvent) -> str:
        """Compute the SHA3-256 chain hash for an event — stored as prior_hash in the next entry.

        Covers the same signing fields as new_event() built for this event's own
        sig_format_version (the "compute once" property, DD4 per-entry dispatch):
        chain hash = sha3_256(DOMAIN_PREFIX + rfc8785.dumps(signing_fields)).hexdigest()
                   = Ed25519 signed digest (as hex)

        The signature field is excluded to avoid circular dependency; chain traversal and
        signature verification are independent proofs that converge on the same digest.
        """
        fields = signing_fields_from_event(event)
        return hashlib.sha3_256(_message_representative(fields)).hexdigest()

    def audit_id(self) -> str:
        return f"urn:aevum:audit:{self.event_id}"
