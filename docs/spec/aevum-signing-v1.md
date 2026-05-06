# Aevum Signing Specification — v1

*This specification defines the canonical form, digest, and signature used
to produce and verify AuditEvent entries in an Aevum sigchain.*

---

## Overview

Every AuditEvent is cryptographically signed. The signature covers a
deterministic subset of the event's fields (the **signing fields**), enabling
verification of event authenticity and chain integrity without relying on
database ordering or application state.

The signing chain provides:

- **Per-event authenticity** — each event is signed with the deployment's
  signing key; forgery requires the private key
- **Chain integrity** — each event references the SHA3-256 digest of the
  signing fields of the previous event; insertion, deletion, or reordering is
  detectable
- **Session boundary transparency** — `session.start` events explicitly declare
  the signing key identity and, for persistent backends, link to the prior
  session's terminal event via `causation_id`

---

## Signing Fields

The signature covers exactly these 16 fields, extracted from the AuditEvent:

```
actor
causation_id
correlation_id
episode_id
event_id
event_type
payload_hash
prior_hash
schema_version
sequence
signer_key_id
span_id
system_time
trace_id
valid_from
valid_to
```

Fields **not** in the signing set: `payload`, `signature`, `audit_id`.

- `payload` is omitted because it is covered by `payload_hash`; signing the
  payload directly would make the signature grow linearly with payload size.
- `signature` is omitted because it is the output of the signing process.
- `audit_id` is omitted because it is derived from `event_id` (same bytes,
  different representation) and would be redundant.

Note: `sequence` and `episode_id` **are** included in the signing set. This
ensures the chain position and episode grouping are tamper-evident.

---

## Digest Computation

### Step 1 — Construct signing object

Extract the 16 signing fields from the AuditEvent. Set absent optional fields
to `null` (JSON null). Do not omit them.

```json
{
  "actor": "aevum-core",
  "causation_id": null,
  "correlation_id": null,
  "episode_id": "01961234-5678-7abc-def0-123456789012",
  "event_id": "01961234-5678-7abc-def0-123456789012",
  "event_type": "session.start",
  "payload_hash": "abc123...64hexchars",
  "prior_hash": "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e",
  "schema_version": "1.0",
  "sequence": 1,
  "signer_key_id": "550e8400-e29b-41d4-a716-446655440000",
  "span_id": null,
  "system_time": 116529853327015936,
  "trace_id": null,
  "valid_from": "2026-05-06T21:54:11.401122+00:00",
  "valid_to": null
}
```

### Step 2 — Canonicalize (RFC 8785 JCS)

Apply JSON Canonicalization Scheme (RFC 8785):

1. Keys sorted by Unicode code-point order (lexicographic ASCII for ASCII keys)
2. No whitespace between tokens
3. Strings as UTF-8 with minimal escaping
4. Numbers: integers as-is; floats in IEEE 754 form (no trailing zeros)
   (In practice, Aevum signing fields contain only strings, integers, and null —
   no floating-point values arise)

The implementation in Python for Aevum's field types is:

```python
import json

canonical_bytes = json.dumps(
    signing_obj,
    sort_keys=True,
    separators=(',', ':'),
    ensure_ascii=False,
).encode('utf-8')
```

This produces identical output to full JCS for the integer, string, and null
types used in Aevum signing fields. If future schema versions introduce float
fields, a dedicated JCS library must be used.

### Step 3 — Hash

```python
import hashlib
digest = hashlib.sha3_256(canonical_bytes).digest()
# digest is 32 bytes (256 bits)
```

### Step 4 — Sign

The signer receives the 32-byte digest. It does NOT re-hash the input.

```python
# InProcessSigner (Ed25519):
raw_signature = private_key.sign(digest)
# digest is passed directly to Ed25519's internal message-processing step

# VaultTransitSigner:
# POST /v1/transit/sign/{key_name}
# body: {"input": base64(digest), "prehashed": true}
```

### Step 5 — Encode

```python
import base64
signature = base64.urlsafe_b64encode(raw_signature).rstrip(b'=').decode()
# Result: base64url without padding, always 86 characters (Ed25519 = 64 bytes)
```

---

## Hash Chain

### Prior hash computation

The `prior_hash` of event N equals the SHA3-256 digest of event N-1's signing
fields — the same 32-byte value that was signed to produce `signature[N-1]`:

```python
import json, hashlib

def hash_event_for_chain(event_dict: dict) -> str:
    """
    Compute the SHA3-256 hex digest of an event's signing fields.

    This is stored as the prior_hash of the NEXT event.
    It is identical to the digest used to produce the event's signature.
    """
    signing_fields = (
        "actor", "causation_id", "correlation_id", "episode_id",
        "event_id", "event_type", "payload_hash", "prior_hash",
        "schema_version", "sequence", "signer_key_id", "span_id",
        "system_time", "trace_id", "valid_from", "valid_to",
    )
    obj = {field: event_dict.get(field) for field in signing_fields}
    canonical = json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')
    return hashlib.sha3_256(canonical).hexdigest()
```

This property means a verifier can reuse the same canonical computation for
both chain-link verification and signature verification, computing the digest
only once per event.

### Genesis hash

The first event in a chain (sequence=1, always a `session.start`) has:

```python
import hashlib
GENESIS_HASH = hashlib.sha3_256(b"aevum:genesis").hexdigest()
# = "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e"
```

### Session boundary hash

When a persistent backend is restarted, a new `session.start` is written. Its
`causation_id` is set to the `audit_id` of the last event in the previous
session. The `prior_hash` links to the SHA3-256 digest of that last event's
signing fields, creating a continuous, verifiable chain across process restarts.

---

## Verification Procedure

A verifier must:

1. Sort events by `sequence` number (ascending)
2. For each event:
   a. Extract the 16 signing fields into a canonical JSON object
   b. Compute `digest = SHA3-256(JCS-canonical(signing_fields))`
   c. Verify `prior_hash` equals the digest computed in step (b) for the
      *previous* event. For the first event: verify `prior_hash` equals
      the genesis hash constant.
   d. Verify Ed25519 signature: `public_key.verify(signature_bytes, digest)`
   e. Verify `payload_hash` equals
      `sha3_256(json.dumps(payload, sort_keys=True, separators=(',',':')).encode())`
   f. Verify `system_time` is >= previous event's `system_time` (HLC monotonicity)
3. Report: pass/fail per event, total events verified, any chain breaks

A reference verifier is provided at `tools/verify/verify_chain.py`.

---

## Signature Encoding

| Property | Value |
|---|---|
| Algorithm | Ed25519 (RFC 8032) |
| Digest input | SHA3-256 (FIPS 202) of JCS-canonical signing fields |
| Signature encoding | base64url without padding (RFC 4648 §5) |
| Public key format | SubjectPublicKeyInfo PEM (32-byte Ed25519 raw key) |

## Key Identification

The `signer_key_id` field identifies the signing key:

- **InProcessSigner**: UUID v4 string, auto-generated at startup
- **VaultTransitSigner**: `{vault_url}/transit/keys/{key_name}[:{version}]`
- **Custom**: any stable string that uniquely identifies the key

Key changes (rotation) are visible as `signer_key_id` changes between events.
Chain hash integrity is not affected by key changes.

---

## GENESIS_HASH constant

```python
import hashlib
GENESIS_HASH = hashlib.sha3_256(b"aevum:genesis").hexdigest()
# "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e"
```

Used as `prior_hash` for the first event in every chain.
