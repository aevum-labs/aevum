"""
aevum.sdk.export.ietf_aat — IETF Agent Audit Trail export adapter.

Serializes Aevum AuditEvents to the format specified in:
    draft-sharif-agent-audit-trail-00
    https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/

The IETF format uses SHA-256 per RFC 8785 JCS canonicalization.
Aevum's internal sigchain uses SHA3-256. This adapter produces
a PARALLEL representation — it does not alter the internal chain.

No new runtime dependencies. JCS is implemented inline.

Usage:
    from aevum.sdk.export.ietf_aat import export_sigchain

    events = engine.get_ledger_events()
    ietf_records = export_sigchain(events)
    # write to file, send to external auditor, etc.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from aevum.core.audit.event import AuditEvent

# Genesis constant for IETF format (distinct from Aevum's internal genesis)
_IETF_GENESIS_HASH = "sha256:" + hashlib.sha256(b"aevum:ietf:genesis").hexdigest()


def _jcs_dumps(obj: dict[str, Any]) -> bytes:
    """
    RFC 8785 JSON Canonicalization Scheme.

    For audit records (no NaN/Infinity/special numbers), this implementation
    is correct and complete. Keys are sorted, no insignificant whitespace,
    UTF-8 encoded.
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_jcs(obj: dict[str, Any]) -> str:
    """SHA-256 over JCS-canonicalized object. Returns 'sha256:<hex>'."""
    return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


def export_audit_event(
    event: AuditEvent,
    prior_ietf_hash: str = _IETF_GENESIS_HASH,
) -> dict[str, Any]:
    """
    Convert a single AuditEvent to IETF Agent Audit Trail format.

    Args:
        event: The AuditEvent to convert.
        prior_ietf_hash: SHA-256 hash of the previous IETF record,
                         or the genesis hash for the first record.

    Returns:
        IETF-format record dict. Not yet chain-hashed (call export_sigchain
        for a complete chain with correct prior_hash values).
    """
    # Extract OTel GenAI model info from payload if present
    model_id: str | None = (
        event.payload.get("gen_ai.request.model")
        or event.payload.get("model_id")
    )
    provider: str | None = event.payload.get("gen_ai.system")

    record: dict[str, Any] = {
        # IETF mandatory fields
        "agent_id": event.actor,
        "action_type": event.event_type,
        "outcome": _infer_outcome(event),
        "timestamp": event.valid_from,
        "prior_hash": prior_ietf_hash,

        # IETF optional fields
        "conversation_id": event.payload.get("gen_ai.conversation.id"),

        # Aevum extension fields (namespaced to avoid collision)
        "aevum:audit_id": event.audit_id(),
        "aevum:episode_id": event.episode_id,
        "aevum:sequence": event.sequence,
        "aevum:schema_version": event.schema_version,
        "aevum:prior_hash_sha3": event.prior_hash,  # internal SHA3-256 chain
        "aevum:payload_hash_sha3": event.payload_hash,
        "aevum:signer_key_id": event.signer_key_id,

        # Model identity (OTel GenAI aligned)
        "gen_ai:request_model": model_id,
        "gen_ai:provider": provider,
    }

    # Remove None values (cleaner output)
    return {k: v for k, v in record.items() if v is not None}


def export_sigchain(events: list[AuditEvent]) -> list[dict[str, Any]]:
    """
    Export a complete Aevum sigchain as IETF Agent Audit Trail records.

    Computes a SHA-256 JCS hash chain over the exported records,
    independent of Aevum's internal SHA3-256 chain.

    Args:
        events: Ordered list of AuditEvents (earliest first).

    Returns:
        List of IETF-format records with correct SHA-256 hash chaining.

    Note:
        The IETF chain is a faithfully derived representation.
        For tamper detection, use engine.verify_sigchain() on the
        internal SHA3-256 chain, which is the authoritative record.
    """
    if not events:
        return []

    records: list[dict[str, Any]] = []
    prior_hash = _IETF_GENESIS_HASH

    for event in events:
        # Build record without self-hash
        record = export_audit_event(event, prior_ietf_hash=prior_hash)

        # Compute this record's chain hash over the record content
        # (excluding the hash of itself — this is the hash of the DATA
        #  that the NEXT record will reference as prior_hash)
        record_hash = _sha256_jcs(record)
        record["chain_hash"] = record_hash

        records.append(record)
        prior_hash = record_hash

    return records


def _infer_outcome(event: AuditEvent) -> str:
    """
    Infer IETF outcome from event_type convention.

    Aevum event_types use dot notation: "ingest.accepted",
    "ingest.barrier_crisis", "query.consent_denied", etc.
    """
    event_type = event.event_type.lower()
    if any(s in event_type for s in (
        "denied", "error", "rejected", "crisis", "failed", "violation"
    )):
        return "failure"
    if any(s in event_type for s in (
        "pending", "review", "waiting", "deferred"
    )):
        return "pending"
    return "success"
