# SPDX-License-Identifier: Apache-2.0
"""aevum.verify._format — wire-format primitives, reimplemented from the public spec.

Every function here is derived from docs/spec/aevum-signing-v1.md, not from
the chain producer's source. This module (together with _core.py) imports
nothing from the producer — that independence is what lets a third party
verify an Aevum sigchain without trusting the operator's runtime. See the
"Hash Chain", "Digest Construction", and "GENESIS_HASH constant" sections of
the spec for the byte-level rules each function below implements.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any

import rfc8785

# Domain separator prepended to every signed representative (spec "Digest
# Construction", Step 3). Binds protocol name + wire-format version into the
# signed bytes.
DOMAIN_PREFIX: bytes = b"aevum-sigchain-v1\x00"

# Genesis prior_hash constant (spec "GENESIS_HASH constant"). Copied as a
# literal — not computed — so this module makes no assumption about how the
# producer derives it.
GENESIS_HASH: str = "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e"

# DoS guard: legitimate hex fields (payload_hash, prior_hash, mldsa65_pub,
# mldsa65_sig, root_hash, tsa_token) are all well under 10K chars even for
# ML-DSA-65 (~6,618 hex chars). This bound is generous headroom, not a tight
# fit, so it rejects hostile multi-MB blobs without touching real data.
MAX_HEX_FIELD_LEN: int = 200_000

# DoS guard: caps how many chain entries a single load_chain() call will
# deserialize. A legitimate forensic export this large would be sharded
# rather than shipped as one JSON blob.
MAX_CHAIN_ENTRIES: int = 250_000


def safe_fromhex(value: str) -> bytes:
    """bytes.fromhex(value), rejecting oversized input before conversion.

    Untrusted hex fields (entry.mldsa65_pub, sth.root_hash, etc.) come from
    the chain file, not a trusted source. Without a length check, a hostile
    multi-megabyte hex string is decoded in full before the verifier gets a
    chance to reject it. Raises ValueError for both malformed hex and
    oversized input — callers already treat ValueError as fail-closed.
    """
    if len(value) > MAX_HEX_FIELD_LEN:
        raise ValueError(f"hex field of {len(value)} chars exceeds {MAX_HEX_FIELD_LEN} limit")
    return bytes.fromhex(value)


def message_representative(fields: dict[str, Any]) -> bytes:
    """DOMAIN_PREFIX + RFC 8785 (JCS) canonical bytes of fields.

    Spec "Digest Construction" Steps 1-3. This is the input to both the
    Ed25519 digest (sha3_256 of this) and the ML-DSA-65 signature (this,
    directly).
    """
    return DOMAIN_PREFIX + rfc8785.dumps(fields)


def hash_payload(payload: dict[str, Any]) -> str:
    """sha3_256 hex digest of the canonical JSON payload.

    Spec "Verification Procedure" step (g): payload_hash equals
    sha3_256(json.dumps(payload, sort_keys=True, separators=(',', ':'))).
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_256(canonical).hexdigest()


def hash_event_for_chain(event: Any) -> str:
    """sha3_256 hex digest of an event's message representative.

    Spec "Hash Chain" section: stored as the next event's prior_hash, and
    identical to the digest Ed25519 signed for this event (the "compute
    once" property). Accepts any object exposing the 19 signing-field
    attributes — both VerifyEvent and the producer's event dataclass qualify.
    """
    fields: dict[str, Any] = {
        "actor": event.actor,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "episode_id": event.episode_id,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "hash_alg": event.hash_alg,
        "key_scheme": event.key_scheme,
        "payload_hash": event.payload_hash,
        "prior_hash": event.prior_hash,
        "schema_version": event.schema_version,
        "sequence": event.sequence,
        "sig_format_version": 1,
        "signer_key_id": event.signer_key_id,
        "span_id": event.span_id,
        # HLC system_time may exceed 2^53; the signing field must be a string.
        "system_time": str(event.system_time),
        "trace_id": event.trace_id,
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
    }
    return hashlib.sha3_256(message_representative(fields)).hexdigest()


@dataclasses.dataclass(frozen=True)
class VerifyEvent:
    """Verifier-local stand-in for the chain producer's event dataclass.

    Carries only the fields _core.py reads (everything event_to_dict
    serializes). Constructed by event_from_dict when loading a chain file —
    the verifier never constructs or imports the producer's event type.
    """

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
    mldsa65_sig: str | None = None
    mldsa65_pub: str | None = None
    tsa_url: str | None = None
    tsa_token: str | None = None
    key_scheme: str = "ed25519"
    sig_format_version: int | None = None
    hash_alg: str = "sha3-256"
