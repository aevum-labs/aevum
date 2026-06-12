# SPDX-License-Identifier: Apache-2.0
"""
AuditEvent — the canonical episodic ledger entry format. Spec Section 06.2.

Every entry written to the sigchain is an AuditEvent. It is immutable (frozen dataclass),
cryptographically signed, and chained to its predecessor via prior_hash. The 18 core fields
are always present; the 6 optional Phase 1 fields carry dual-sig and TSA data and are
nullable on pre-Phase-1 entries to preserve backward compatibility across versions.

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
from typing import Any


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    """Immutable episodic ledger entry. Core 18 fields + 6 optional Phase 1 dual-sig fields.

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
    # is not 1 (including None). Kept as a forward-evolution signal (P2g may introduce 2).
    sig_format_version: int | None = None
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

        Covers the same 18 fields as new_event()'s signing_fields (the "compute once" property):
        chain-link hash == signed digest, so altering any signed field breaks both proofs at once.

        The signature field is excluded to avoid a circular dependency; chain traversal and
        signature verification remain independent proofs.

        Serialisation: RFC 8785 JCS (sort_keys=True + compact separators) for determinism.
        """
        fields = {
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
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": 1,
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha3_256(canonical).hexdigest()

    def audit_id(self) -> str:
        return f"urn:aevum:audit:{self.event_id}"
