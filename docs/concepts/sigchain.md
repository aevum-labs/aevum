---
description: "The episodic ledger's Ed25519 + SHA3-256 sigchain: 18-field AuditEvent schema, hash chaining, tamper detection, Hybrid Logical Clock timestamps."
---

# The Episodic Ledger and Sigchain

The episodic ledger is the canonical truth of every AI decision. It is
append-only, cryptographically signed, and hash-chained. Nothing can be
removed or modified after it is written.

## The 18-field AuditEvent

Every entry in the ledger is an `AuditEvent` with exactly 18 fields:

| Field | Type | Description |
|---|---|---|
| `event_id` | str | UUID v7 (time-ordered) |
| `episode_id` | str | Groups related events into an "episode" |
| `sequence` | int | Monotonically increasing, per-chain (starts at 1) |
| `event_type` | str | e.g. `"ingest"`, `"query"`, `"credit.issued"` |
| `schema_version` | str | Always `"1.0"` in this release |
| `valid_from` | str | ISO 8601 — when the event became valid |
| `valid_to` | str \| None | ISO 8601 — optional validity end |
| `system_time` | int | Hybrid Logical Clock timestamp (nanoseconds) |
| `causation_id` | str \| None | `audit_id` of the event that caused this one |
| `correlation_id` | str \| None | Trace correlation across multiple events |
| `actor` | str | Who performed the operation (required, non-empty) |
| `trace_id` | str \| None | OpenTelemetry trace ID |
| `span_id` | str \| None | OpenTelemetry span ID |
| `payload` | dict | The operation's data (what was ingested, queried, etc.) |
| `payload_hash` | str | SHA3-256 of the canonical JSON payload |
| `prior_hash` | str | SHA3-256 hash of all fields of the previous event |
| `signature` | str | Ed25519 signature over all fields except `signature` |
| `signer_key_id` | str | UUID of the Ed25519 private key that signed this event |

## How the chain works

Each event includes the hash of the previous event. Modifying any event
breaks the chain from that point forward, making tampering detectable.

```
Genesis hash = SHA3-256("aevum:genesis")
     ↓
Event 1:  prior_hash = genesis_hash
          payload_hash = SHA3-256(event1.payload)
          signature = Ed25519(all fields except signature)
          chain_hash_1 = SHA3-256(all fields except signature)
     ↓
Event 2:  prior_hash = chain_hash_1
          ...
     ↓
Event N:  prior_hash = chain_hash_{N-1}
          ...
```

To verify that the chain is intact from genesis to the current state:

```python
intact = engine.verify_sigchain()
# True  = every event is unmodified and correctly linked
# False = tampering detected or signing key changed without rotation
```

## The audit_id format

Every `OutputEnvelope` includes an `audit_id` that identifies the ledger entry:

```
urn:aevum:audit:0196f2a1-1234-7abc-8def-0123456789ab
               ^         ^
               |         UUID v7 (time-ordered, ~1ms resolution)
               Namespace prefix (frozen invariant)
```

UUID v7 is time-ordered, which means audit IDs sort chronologically.

## Verifying the chain

```python
engine = Engine()

# ... operations ...

# Full chain verification
intact = engine.verify_sigchain()
if not intact:
    print("WARNING: sigchain integrity check failed")
```

`verify_sigchain()` re-verifies:
1. That `prior_hash` in each event matches the computed hash of the previous event
2. That `payload_hash` in each event matches the SHA3-256 of the actual payload
3. That the Ed25519 `signature` in each event is valid over the signing fields

All three checks must pass for the chain to be considered intact.

## What tamper detection looks like

If a ledger entry is modified after writing, `verify_sigchain()` returns `False`.

The check fails at the first inconsistency. To identify which event was tampered:

```python
events = engine.get_ledger_entries()
for e in events:
    print(e["sequence"], e["audit_id"], e["event_type"])
# The last valid event is the one before the chain breaks
```

If you are using a persistent backend, check for direct database modifications.
The signing key (`signer_key_id`) should not change between events unless a
deliberate key rotation was performed.

## The "episode" terminology

An **episode** is a group of related audit events that together represent a
complete AI decision or workflow. For example:

```
episode_id: "ep-billing-INV-001"
  event 1: ingest — invoice data ingested
  event 2: query  — billing status retrieved
  event 3: review — credit approval requested
  event 4: review — credit approved by manager
  event 5: commit — credit.issued recorded
```

To group events into an episode, pass `episode_id` to each function call:

```python
ep = "ep-billing-INV-001"
engine.ingest(..., episode_id=ep)
engine.query(..., episode_id=ep)
engine.commit(..., episode_id=ep)
```

Episodes make it possible to replay an entire workflow (not just a single event)
and to understand the full context of any past decision.

## Hybrid Logical Clock

The `system_time` field uses a Hybrid Logical Clock (HLC), not wall time.
HLC advances monotonically even if the system clock is adjusted, preventing
sequence-ordering anomalies in distributed deployments.

The `valid_from` field uses wall time (ISO 8601) for human-readable timestamps.
The `system_time` field uses HLC nanoseconds for ordering guarantees.
