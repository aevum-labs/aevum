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
  message representative of the previous event; insertion, deletion, or
  reordering is detectable
- **Session boundary transparency** — `session.start` events explicitly declare
  the signing key scheme and, for persistent backends, link to the prior
  session's terminal event via `causation_id`

---

## Signing Fields

The signature covers exactly these **19 fields**, extracted from the AuditEvent:

```
actor
causation_id
correlation_id
episode_id
event_id
event_type
hash_alg
key_scheme
payload_hash
prior_hash
schema_version
sequence
sig_format_version
signer_key_id
span_id
system_time
trace_id
valid_from
valid_to
```

Fields **not** in the signing set: `payload`, `signature`, `mldsa65_sig`,
`mldsa65_pub`, `tsa_url`, `tsa_token`, `receipt_cbor`, `audit_id`.

- `payload` is omitted because it is covered by `payload_hash`; signing the
  payload directly would make the signature grow linearly with payload size.
- `signature` is omitted because it is the output of the signing process.
- `mldsa65_sig` / `mldsa65_pub` are omitted because they are outputs of the
  ML-DSA signing pass that runs after the signing fields are canonicalized.
- `tsa_url` / `tsa_token` are omitted because they are RFC 3161 outputs appended
  after the entry is signed.
- `receipt_cbor` is omitted because it is a transparency log receipt appended
  after the entry is written.
- `audit_id` is omitted because it is derived from `event_id` (same bytes,
  different representation) and would be redundant.

Note: `sequence`, `episode_id`, `key_scheme`, `sig_format_version`, and
`hash_alg` are included to make the chain position, episode grouping, algorithm
posture, field-set version, and hash algorithm tamper-evident.

### Signing field encodings

| Field | Type in JSON entry | Encoding in signing fields |
|---|---|---|
| `actor` | string | string (UTF-8) |
| `causation_id` | string \| null | string \| null |
| `correlation_id` | string \| null | string \| null |
| `episode_id` | string | string |
| `event_id` | string (UUID v7) | string |
| `event_type` | string | string |
| `hash_alg` | string, const `"sha3-256"` | string |
| `key_scheme` | string | string |
| `payload_hash` | string (64 hex chars) | string |
| `prior_hash` | string (64 hex chars) | string |
| `schema_version` | string, const `"1.0"` | string |
| `sequence` | integer | integer |
| `sig_format_version` | integer, const `1` | integer, always `1` |
| `signer_key_id` | string | string |
| `span_id` | string \| null | string \| null |
| `system_time` | integer (HLC nanoseconds) | **string** — `str(system_time)` |
| `trace_id` | string \| null | string \| null |
| `valid_from` | string (ISO 8601) | string |
| `valid_to` | string \| null | string \| null |

**`system_time` safe-integer rule:** HLC (Hybrid Logical Clock) values are
nanosecond-precision integers that commonly exceed 2^53-1, the RFC 8785
safe-integer domain. The signing field must be `str(system_time)` — the decimal
string representation — not the raw integer. Passing the raw integer to the
RFC 8785 canonicalizer is a hard error. The JSON entry carries the integer;
the signing field set carries the string.

---

## Digest Construction

### Step 1 — Construct signing object

Extract the 19 signing fields from the AuditEvent. Set absent optional fields
to `null` (JSON null). Do not omit them. Apply the encoding rules from the table
above — in particular, convert `system_time` to its decimal string.

```json
{
  "actor": "aevum-core",
  "causation_id": null,
  "correlation_id": null,
  "episode_id": "01961234-5678-7abc-def0-123456789012",
  "event_id": "01961234-5678-7abc-def0-123456789012",
  "event_type": "session.start",
  "hash_alg": "sha3-256",
  "key_scheme": "ed25519",
  "payload_hash": "abc123...64hexchars",
  "prior_hash": "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e",
  "schema_version": "1.0",
  "sequence": 1,
  "sig_format_version": 1,
  "signer_key_id": "550e8400-e29b-41d4-a716-446655440000",
  "span_id": null,
  "system_time": "1746568451401122816",
  "trace_id": null,
  "valid_from": "2026-05-06T21:54:11.401122+00:00",
  "valid_to": null
}
```

### Step 2 — Canonicalize with RFC 8785 (JCS)

Apply the JSON Canonicalization Scheme (RFC 8785) using the `rfc8785` library:

```python
import rfc8785

canonical_bytes = rfc8785.dumps(signing_obj)
# Returns bytes; keys sorted by Unicode code point; no whitespace;
# non-ASCII characters appear as UTF-8 bytes (NOT \uXXXX escapes).
```

**Do not use `json.dumps` as a substitute.** `json.dumps` with `ensure_ascii=True`
(the default) escapes non-ASCII characters as `\uXXXX`, producing different bytes
from RFC 8785 for any non-ASCII actor, correlation ID, or similar field. Use the
`rfc8785` library unconditionally.

Floats are forbidden in signing fields — the canonicalizer raises on any float
value. All Aevum signing fields are strings, integers, or null.

### Step 3 — Prepend domain prefix

Construct the **message representative** by prepending the domain separator:

```python
DOMAIN_PREFIX = b"aevum-sigchain-v1\x00"

representative = DOMAIN_PREFIX + canonical_bytes
```

The `\x00` byte separates the ASCII prefix from the RFC 8785 JSON body,
eliminating any parsing ambiguity. This domain prefix binds the protocol name
and wire-format version into every signed byte, preventing cross-protocol
signature misuse. `sig_format_version` handles field-set evolution; this prefix
handles protocol/wire-format domain.

### Step 4 — Hash

```python
import hashlib

digest = hashlib.sha3_256(representative).digest()
# digest is 32 bytes (256 bits)
```

This 32-byte digest is the **Ed25519 signed digest** and the **chain hash input**
(compute-once property). The digest is computed once and reused for both proofs:
altering any signing field breaks both the signature check and the chain-linkage
check simultaneously.

### Step 5 — Sign (Ed25519)

The signer receives the 32-byte digest. It does NOT re-hash the input.

```python
# InProcessSigner (Ed25519):
raw_signature = private_key.sign(digest)
# digest is passed directly to Ed25519's internal message-processing step

# VaultTransitSigner:
# POST /v1/transit/sign/{key_name}
# body: {"input": base64(digest), "prehashed": true}
```

### Step 6 — Encode

```python
import base64
signature = base64.urlsafe_b64encode(raw_signature).rstrip(b'=').decode()
# Result: base64url without padding, always 86 characters (Ed25519 = 64 bytes)
```

---

## Hybrid Signing (ML-DSA-65)

Hybrid entries (`key_scheme = "ed25519+ml-dsa-65"`) carry a second signature
produced by ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) over the **message
representative** — not its hash:

```python
mldsa65_raw_sig = ml_dsa_private_key.sign(representative)
# ML-DSA-65 signs representative directly (not sha3_256(representative))
```

The resulting bytes are hex-encoded and stored as `mldsa65_sig`. The public key
bytes are hex-encoded and stored as `mldsa65_pub`.

### Algorithm agility

The `key_scheme` field encodes the posture: `"ed25519"` for classical;
`"ed25519+<level>"` for hybrid, where `<level>` is the ML-DSA level suffix
(currently `"ml-dsa-65"`). The verifier uses this string to select the ML-DSA
algorithm:

```
"ed25519+ml-dsa-65"  →  ML-DSA-65 (OQS: "ML-DSA-65")
```

Any unrecognized `<level>` suffix must cause a **verification failure** — fail
closed, never warn-and-fallback.

### Fail-closed rule

If `key_scheme` is `"ed25519+<level>"` and `mldsa65_sig` or `mldsa65_pub` is
null or absent, the entry **must be rejected**. A missing ML-DSA signature on a
hybrid entry indicates a tamper or downgrade attack; it is never valid to verify
only the Ed25519 portion on a hybrid entry.

### Chain homogeneity

All events in a chain must share the same `key_scheme`. A chain with mixed
schemes must be rejected. Signed posture-change transitions are not supported
in v0.8.0.

---

## Hash Chain

### Prior hash computation

The `prior_hash` of event N equals the hex-encoded SHA3-256 digest of the
message representative of event N-1. This is identical to the digest used to
produce event N-1's Ed25519 signature:

```python
import rfc8785, hashlib

DOMAIN_PREFIX = b"aevum-sigchain-v1\x00"

def hash_event_for_chain(event_dict: dict) -> str:
    """
    Compute the SHA3-256 hex digest of an event's message representative.

    This is stored as the prior_hash of the NEXT event and is identical
    to the digest over which Ed25519 signed.
    """
    signing_fields = {
        "actor":            event_dict["actor"],
        "causation_id":     event_dict.get("causation_id"),
        "correlation_id":   event_dict.get("correlation_id"),
        "episode_id":       event_dict["episode_id"],
        "event_id":         event_dict["event_id"],
        "event_type":       event_dict["event_type"],
        "hash_alg":         event_dict["hash_alg"],
        "key_scheme":       event_dict["key_scheme"],
        "payload_hash":     event_dict["payload_hash"],
        "prior_hash":       event_dict["prior_hash"],
        "schema_version":   event_dict["schema_version"],
        "sequence":         event_dict["sequence"],
        "sig_format_version": 1,
        "signer_key_id":    event_dict["signer_key_id"],
        "span_id":          event_dict.get("span_id"),
        "system_time":      str(event_dict["system_time"]),  # HLC → string
        "trace_id":         event_dict.get("trace_id"),
        "valid_from":       event_dict["valid_from"],
        "valid_to":         event_dict.get("valid_to"),
    }
    representative = DOMAIN_PREFIX + rfc8785.dumps(signing_fields)
    return hashlib.sha3_256(representative).hexdigest()
```

This property means a verifier computes the representative once per event and
derives both the chain-link verification digest and the signature verification
digest from the same bytes.

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
message representative, creating a continuous, verifiable chain across process
restarts.

---

## Verification Procedure

A verifier must:

1. Sort events by `sequence` number (ascending)
2. Pre-check: every entry must have `sig_format_version == 1` (reject None or
   any other value — no fallback, no legacy path)
3. Pre-check: every entry must share the same `key_scheme` (chain homogeneity)
4. For each event:
   a. Construct the 19-field signing object applying encoding rules (see table
      above — `system_time` as string, absent nullable fields as null)
   b. Compute `representative = DOMAIN_PREFIX + rfc8785.dumps(signing_fields)`
   c. Compute `digest = SHA3-256(representative)` (32 bytes)
   d. Verify `prior_hash` equals `sha3_256(representative_of_previous_event).hexdigest()`.
      For the first event: verify `prior_hash` equals the genesis hash constant.
   e. Verify Ed25519 signature:
      `public_key.verify(base64url_decode(signature), digest)`
   f. If `key_scheme` starts with `"ed25519+"`:
      - Parse the level suffix (e.g. `"ml-dsa-65"`)
      - Map to OQS algorithm name; unknown suffix → reject (fail closed)
      - Verify `mldsa65_sig` and `mldsa65_pub` are non-null; null → reject
      - Verify ML-DSA signature:
        `ml_dsa_verify(representative, bytes.fromhex(mldsa65_sig), bytes.fromhex(mldsa65_pub))`
      - Verify `mldsa65_pub` matches the pinned ML-DSA public key (out-of-band)
   g. Verify `payload_hash` equals
      `sha3_256(json.dumps(payload, sort_keys=True, separators=(',',':')).encode()).hexdigest()`
   h. Verify `system_time` is >= previous event's `system_time` (HLC monotonicity)
5. Report: pass/fail per event, total events verified, any chain breaks

A standalone reference verifier is provided by the `aevum-verify` package
(shares no code with `aevum-core` — every primitive above is reimplemented
directly from this spec):

```bash
pip install aevum-verify
aevum-verify CHAIN_FILE --ed25519-pub HEX [--mldsa65-pub HEX]
```

See [`packages/aevum-verify`](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-verify)
for the Python API and full CLI reference.

---

## Trust Model

### Pinned-key anchor

The verifier's trust anchor is the **published Ed25519 public key** (and the
ML-DSA-65 public key for hybrid entries) supplied **out-of-band** — for example,
from the operator's published key material, a hardware security module, or a
key management service.

For hybrid entries, the `mldsa65_pub` embedded in each entry must **equal** the
pinned ML-DSA public key. A mismatch must cause a verification failure.

### `signer_key_id` is informational

`signer_key_id` is a **signed field** (included in the digest) that carries a
human-readable key label. It is NOT the key-identity check. A verifier must not
accept an entry based solely on a matching `signer_key_id` — it must verify the
cryptographic signature against the pinned public key.

`signer_key_id` is useful for log browsing and key-rotation audit trails (you
can see which key label was in use for a given run), but it does not constitute
a security boundary by itself. Key rotations are detectable because `signer_key_id`
changes, and chain continuity is preserved because `prior_hash` still links
correctly across key changes.

### Out-of-band key distribution

Public keys must be distributed through a channel independent of the sigchain
(e.g., a corporate PKI, a hardware attestation, or a separately signed manifest).
A sigchain is self-describing but NOT self-authenticating with respect to key
identity — a forger who controls the chain can also control `signer_key_id`.

---

## Signature Encoding

| Property | Value |
|---|---|
| Algorithm | Ed25519 (RFC 8032) |
| Signed input | SHA3-256 (FIPS 202) of `DOMAIN_PREFIX + rfc8785.dumps(19 signing fields)` |
| Signature encoding | base64url without padding (RFC 4648 §5) |
| Public key format | SubjectPublicKeyInfo PEM (32-byte Ed25519 raw key) |
| ML-DSA algorithm | ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204 draft) |
| ML-DSA input | `DOMAIN_PREFIX + rfc8785.dumps(19 signing fields)` (representative, not its hash) |
| ML-DSA public key encoding | Hex (stored as `mldsa65_pub`) |

---

## Verifiable-Log Layer

### Merkle tree structure

Aevum implements a RFC 6962-style Merkle tree over the append-only sigchain
using SHA3-256 (consistent with the chain hash algorithm).

**Leaf hash:** `sha3_256(0x00 || bytes.fromhex(hash_event_for_chain(event)))`
**Node hash:** `sha3_256(0x01 || left_child_hash || right_child_hash)`
**Empty tree root:** `sha3_256(b"")` (MTH of 0 entries, per RFC 6962)
**Tree shape:** complete binary tree; split point `k = 1 << ((n-1).bit_length()-1)`
(largest power of 2 less than n), per RFC 6962 §2.1.

### Signed Tree Head (STH)

A Signed Tree Head commits to the full log state: `tree_size`, `root_hash`,
`timestamp` (wall-clock), `signer_key_id`, and `key_scheme`.

STHs use their own domain prefix `b"aevum-sth-v1\x00"` — intentionally distinct
from `b"aevum-sigchain-v1\x00"` — providing type-level cross-domain separation:
an entry signature cannot verify as an STH signature and vice versa.

Signing follows the same hybrid pattern as entry signing:
- Ed25519 signs `sha3_256(b"aevum-sth-v1\x00" + rfc8785.dumps(sth_fields))`
- ML-DSA-65 (if configured) signs the representative directly

### Inclusion proofs

An inclusion proof for entry at index `leaf_index` in a tree of size `tree_size`
is a list of sibling hashes that allows a verifier to reconstruct the root hash
from the leaf hash alone, per RFC 6962 §2.1.1.

The verifier re-derives the leaf hash from `hash_event_for_chain(event)` and
walks the proof path to the root, checking that the computed root matches the
STH root.

### Consistency proofs

A consistency proof between two tree states (old tree of size `first`, new tree
of size `second`) allows a verifier to confirm that the new tree is an extension
of the old tree with no edits, per RFC 6962 §2.1.2.

### TSA anchoring

The Signed Tree Head carries an optional `tsa_token` (hex-encoded RFC 3161 DER
bytes) timestamped over the 32-byte Merkle root by an external Timestamp
Authority. This is independent of the self-asserted `timestamp` field — both
claims coexist in the STH.

**TSA cert-chain validation:** full validation of the TSA certificate chain
against a **pinned TSA root** is the responsibility of the standalone verifier.
The `aevum-core` library checks only that the message imprint in the token
matches the Merkle root — it does not perform cert-chain trust evaluation.

A TSA outage never blocks STH production: if the TSA request fails, the STH is
issued without a timestamp token and `tsa_token` is null.

---

## GENESIS_HASH constant

```python
import hashlib
GENESIS_HASH = hashlib.sha3_256(b"aevum:genesis").hexdigest()
# "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e"
```

Used as `prior_hash` for the first event in every chain.
