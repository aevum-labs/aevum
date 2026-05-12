"""
AuditEvent — the episodic ledger entry. Spec Section 06.2.
Phase 1 adds 6 optional dual-sig + TSA fields (nullable for backward compat).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    """Immutable episodic ledger entry. Core 18 fields + 6 optional Phase 1 dual-sig fields."""

    event_id: str
    episode_id: str
    sequence: int
    event_type: str
    schema_version: str
    valid_from: str
    valid_to: str | None
    system_time: int
    causation_id: str | None
    correlation_id: str | None
    actor: str
    trace_id: str | None
    span_id: str | None
    payload: dict[str, Any]
    payload_hash: str
    prior_hash: str
    signature: str
    signer_key_id: str
    # Phase 1: dual-sig fields (nullable — absent on pre-Phase-1 entries)
    ed25519_sig: str | None = None   # hex, 128 chars
    mldsa65_sig: str | None = None   # hex, 6618 chars
    ed25519_pub: str | None = None   # hex, 64 chars
    mldsa65_pub: str | None = None   # hex, 3904 chars
    tsa_url: str | None = None
    tsa_token: str | None = None     # hex of DER bytes

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
        """SHA3-256 over all fields (excluding signature) for prior_hash chaining."""
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
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha3_256(canonical).hexdigest()

    def audit_id(self) -> str:
        return f"urn:aevum:audit:{self.event_id}"
