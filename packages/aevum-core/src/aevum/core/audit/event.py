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


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    """Immutable episodic ledger entry. 19 signed fields (16 base + key_scheme +
    sig_format_version + hash_alg) plus optional Phase 1 dual-sig attachment fields
    (mldsa65_sig, mldsa65_pub, tsa_url, tsa_token, receipt_cbor).

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

        Covers the same 19 fields as new_event()'s signing_fields (the "compute once" property):
        chain hash = sha3_256(DOMAIN_PREFIX + rfc8785.dumps(19 fields)).hexdigest()
                   = Ed25519 signed digest (as hex)

        The signature field is excluded to avoid circular dependency; chain traversal and
        signature verification are independent proofs that converge on the same digest.
        """
        fields: dict[str, Any] = {
            "event_id": event.event_id,
            "episode_id": event.episode_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "valid_from": event.valid_from,
            "valid_to": event.valid_to,
            # system_time is a HLC integer that may exceed 2^53; encode as string for RFC 8785.
            "system_time": str(event.system_time),
            "causation_id": event.causation_id,
            "correlation_id": event.correlation_id,
            "actor": event.actor,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": 1,
            "hash_alg": event.hash_alg,
        }
        return hashlib.sha3_256(_message_representative(fields)).hexdigest()

    def audit_id(self) -> str:
        return f"urn:aevum:audit:{self.event_id}"
