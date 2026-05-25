# ADR-010: Three-Tier Receipt Storage — SQLite WAL

Date: 2026-05-25
Status: Accepted
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

Session 1A introduced COSE_Sign1 receipt encoding (ADR-009). Those encoded bytes
needed a storage layer. The requirements were:

1. **Crash protection** — certain events (POLICY_DENY, human override REJECT,
   MINIMUM_RISK handoff) must survive operational data rotation. These are the
   DSSAD-equivalent "why it happened" records.
2. **Rolling operational window** — routine receipts need a configurable retention
   window (default 48 hours) to prevent unbounded growth.
3. **Long-term compliance** — EU AI Act Art. 26(6) requires minimum 6-month
   retention for high-risk AI system logs.
4. **Single-file simplicity** — backup, restore, and inspection must be tractable
   for a single-process deployment.
5. **RDF queryability** — receipt metadata must remain queryable via the Oxigraph
   provenance graph (urn:aevum:provenance) without duplicating blobs there.

## Options Considered

### Option A: Oxigraph provenance graph (rejected)

Store COSE_Sign1 bytes as xsd:base64Binary literals in urn:aevum:provenance.

**Rejected because:**
- Oxigraph is described by its author as a "hobby project" — no published
  production throughput benchmark.
- Oxigraph is single-writer; concurrent ingestion pipelines would contend.
- RDF triple stores are optimized for graph traversal, not blob storage.
- 110,490 inserts/sec measured for SQLite WAL (Session 1A pre-flight benchmark
  in docs/learn/performance.md) vs. no comparable Oxigraph figure.

### Option B: Separate SQLite files per tier (rejected)

One file for `operational`, one for `crash_protected`, one for `long_term`.

**Rejected because:**
- Three backup targets instead of one.
- Tier promotion requires cross-file copy, not a single UPDATE.
- Inspection requires querying three files.
- Lock semantics must be coordinated across files.

### Option C: One SQLite WAL file, tier column (accepted)

Single file (AEVUM_RECEIPT_DB). Tier separation is logical (a `tier` column
and a `locked` flag), not physical.

**Selected because:**
- One backup target.
- Tier promotion = `UPDATE receipts SET tier='long_term' WHERE ...` — no I/O copy.
- Crash protection = `UPDATE receipts SET locked=1, tier='crash_protected'` — atomic.
- SQLite WAL: 110,490 inserts/sec (Session 1A benchmark). Sufficient for all
  single-process agent deployments.
- Simple inspection: `sqlite3 receipts.db "SELECT tier, count(*) FROM receipts GROUP BY tier"`.

## Decision Outcome

**Three-tier SQLite WAL store** implemented as `SqliteReceiptStore` in
`aevum.core.sqlite_store`.

### Schema

```sql
CREATE TABLE receipts (
    receipt_hash    TEXT    NOT NULL PRIMARY KEY,  -- SHA3-256(COSE_Sign1 bytes) hex
    blob            BLOB    NOT NULL,               -- raw COSE_Sign1 bytes
    stored_at       REAL    NOT NULL,               -- Unix timestamp float
    entry_hash      TEXT    NOT NULL DEFAULT '',    -- sigchain_entry_hash cross-ref
    rekor_entry_ref TEXT    NOT NULL DEFAULT '',    -- Rekor UUID/URL (empty = not submitted)
    tier            TEXT    NOT NULL DEFAULT 'operational',
    locked          INTEGER NOT NULL DEFAULT 0,     -- 0=unlocked, 1=crash_protected
    created_at      REAL    NOT NULL
);

CREATE TABLE ambient_receipts (
    snapshot_id TEXT    NOT NULL PRIMARY KEY,
    blob        BLOB    NOT NULL,
    stored_at   REAL    NOT NULL,
    session_id  TEXT    NOT NULL,
    trigger     TEXT    NOT NULL,
    tier        TEXT    NOT NULL DEFAULT 'operational'
);
```

PRAGMA settings on every connection: `journal_mode=WAL`, `synchronous=NORMAL`,
`foreign_keys=ON`.

### Three Tiers

| Tier | locked | Rotation | Trigger |
|------|--------|----------|---------|
| `crash_protected` | 1 | Never | POLICY_DENY, HUMAN_OVERRIDE_REJECT, MINIMUM_RISK, SYSTEM_FAILURE, ODD_EXIT |
| `operational` | 0 | 48h rolling (configurable) | Default for all new receipts |
| `long_term` | 0 | Not implemented this session | Promoted from operational via `rotate_operational()` |

### Lock Mechanism

`SqliteReceiptStore.lock()` sets `locked=1` and `tier='crash_protected'`.
- **Idempotent** — locking an already-locked receipt is safe (no-op).
- **Permanent** — there is no `unlock()` method. Demotion requires an ADR-level decision.
- Raises `ReceiptNotFoundError` if the hash does not exist.

### Escalation Trigger Logic

`aevum.core.escalation` implements `should_escalate()` and
`escalate_if_triggered()`. These are called by `SigChain.new_event()` immediately
after storing a receipt in the operational tier. If escalation conditions are met,
`store.lock(receipt_hash)` is called automatically.

Escalation failure is non-blocking — a warning is logged but the event is not
blocked. The receipt remains in the operational tier if the escalation check fails.

### RDF Cross-References

Receipt blobs live in SQLite. Receipt metadata lives in `urn:aevum:provenance`
(Oxigraph) as RDF quads:

```
Subject: <urn:aevum:receipt:{receipt_hash}>

aevum:receiptHash   "{receipt_hash}"^^xsd:string
aevum:storedTier    "{tier}"^^xsd:string
aevum:isLocked      {true|false}^^xsd:boolean
aevum:rekorRef      "{rekor_entry_ref}"^^xsd:string
```

This preserves SPARQL queryability of provenance metadata without duplicating blobs
in the RDF store. Callers with both stores call `OxigraphStore.store_receipt_ref()`
after `SqliteReceiptStore.put()`.

### WORM-Backend Option (Deferred)

When `AEVUM_RECEIPT_WORM_URL` is set, crash_protected receipts should be replicated
off-host (S3 Object Lock, Azure Immutable Blob, GCS Object Retention). This is
documented in `.env.example` but **not implemented in this session**. Planned for
v0.8. The SQLite `locked=1` flag is the crash-protection mechanism until WORM
replication is implemented.

### PostgresReceiptStore Stub

SQLite WAL does not support concurrent writers across OS processes. For multi-process
agent deployments (e.g., multiple worker processes sharing a single receipt store),
`PostgresReceiptStore` must be used. A stub is provided in `aevum.core.store` that
raises `NotImplementedError` with a clear message directing users to the tracking
issue. Implementation is planned for a future session.

### Maintenance

`SqliteReceiptStore.rotate_operational(hours=48)` promotes operational receipts
older than `hours` to `long_term`. It is NOT called automatically. Deployers must
invoke it on a schedule (recommended: daily via cron or maintenance session).

Failure to run `rotate_operational()` will cause unbounded growth of the
operational tier. The `long_term` tier is not automatically deleted — EU AI Act
Art. 26(6) requires minimum 6-month retention. Retention policies beyond the
minimum are the deployer's responsibility.

## Consequences

### Positive

- Single-file backup/restore for all three tiers.
- Atomic tier transitions via SQL UPDATE.
- DSSAD-equivalent crash protection for regulatory-critical events.
- 110,490 inserts/sec — sufficient for all single-process deployments.
- SQLite is available everywhere Python runs — zero additional dependencies.
- `rotate_operational()` gives deployers full control over operational-tier growth.

### Negative / risks

- SQLite WAL: one writer at a time. Multi-process deployments must use Postgres
  (not yet implemented).
- `rotate_operational()` must be scheduled externally — no built-in scheduler.
- Long-term tier is permanent (no auto-delete) — deployers must manage growth.
- WORM replication deferred — crash_protected receipts are only as durable as the
  local SQLite file until v0.8.

### Open Questions

- When should Postgres support be added? **Proposed: v0.8**, driven by first
  multi-process deployment need.
- Should `rotate_operational()` be configurable per-tier? **No** — the EU AI Act
  minimum for long_term is non-negotiable; only the operational window is configurable.
- Should ambient receipts be tiered separately? **No** — ambient receipts always
  start in the operational tier; escalation is not yet wired for ambient receipts.

## Related ADRs

- ADR-001 (Single sigchain — events whose receipts are stored here)
- ADR-003 (OR-set consent — not related to receipt storage)
- ADR-007 (Transparency log — Rekor entry UUID stored as rekor_entry_ref)
- ADR-009 (Black box receipt format — the COSE_Sign1 blob stored in this tier)

## References

- Session 1A benchmark results: `docs/learn/performance.md`
- ADR-009 receipt_hash derivation: SHA3-256(COSE_Sign1 bytes) hexdigest
- VDR maritime model: IMO MSC.333(90) — crash-protected data recorder survivability
- EU AI Act Art. 26(6): 6-month minimum log retention for high-risk AI systems
- UNECE WP.29 UN R157 DSSAD: "why it happened" data for automated driving handoffs
