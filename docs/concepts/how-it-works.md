# How It Works

Aevum is a replay-first, policy-governed context kernel. This page explains
the data flow from raw input to governed output.

## The big picture

Every piece of data entering Aevum passes through the same path:

```
Your data source
      ↓
  governed membrane  ← Barriers 3 (consent) and 5 (provenance) checked here
      ↓
  knowledge graph    ← urn:aevum:knowledge  (working data)
      ↓
  episodic ledger    ← urn:aevum:provenance (immutable audit, sigchain)
      ↓
  consent ledger     ← urn:aevum:consent    (OR-Set grants)
```

When an agent queries context, traversal goes through the same governed
path in reverse — consent is checked before any graph traversal begins.

## The three named graphs

Aevum maintains exactly three named graphs. These URIs are frozen invariants.

| Graph URI | Contents | Mutable? |
|---|---|---|
| `urn:aevum:knowledge` | Working data — entities, relationships | Yes (via ingest) |
| `urn:aevum:provenance` | Every audit event, sigchain | Never (append-only) |
| `urn:aevum:consent` | Consent grants and revocations | Append-only |

## Step-by-step data flow

### 1. Ingest

An agent calls `engine.ingest()` with data, provenance, a purpose, and a subject ID.

Before anything is written:

1. **Barrier 5 (Provenance)** — `provenance.source_id` must be present. If missing → error.
2. **Barrier 3 (Consent)** — the `grantee_id` must hold an active grant for `ingest` on `subject_id`. If not → error.
3. **Barrier 1 (Crisis)** — the payload text is scanned for crisis keywords. If found → crisis envelope, operation halted.
4. **Barrier 2 (Classification Ceiling)** — enforced at query time (see below).

If all checks pass:
- Data is written to `urn:aevum:knowledge`
- An `AuditEvent` is created, signed with Ed25519, chained with SHA3-256, and appended to `urn:aevum:provenance`
- An `OutputEnvelope` with `status="ok"` and a `audit_id` (URN) is returned

### 2. Query

An agent calls `engine.query()` with a purpose, list of subject IDs, and an actor.

1. **Barrier 3 (Consent)** — checked for each `subject_id` in the list
2. **Barrier 2 (Classification Ceiling)** — results above `classification_max` are redacted, not errored

The result is an `OutputEnvelope` whose `data["results"]` is a dict keyed by subject ID.

### 3. Review

An agent calls `engine.review()` when it needs human approval for an action.
The call creates a pending review record. A human later calls `engine.review(action="approve")` or `engine.review(action="veto")`.

The default is veto. If the deadline passes without a human decision, the action is blocked.

### 4. Commit

An agent calls `engine.commit()` to record a named event in the episodic ledger.
This is a write-only operation — it appends to `urn:aevum:provenance`.

Use `commit` to record business events: "credit issued", "policy approved", "document signed".

### 5. Replay

An agent calls `engine.replay(audit_id=...)` to deterministically reconstruct
any past ledger entry. The payload is retrieved from `urn:aevum:provenance` and
returned in `data["replayed_payload"]`.

Replay requires a consent grant with `"replay"` in the operations list.

## The OutputEnvelope

Every function returns exactly one `OutputEnvelope`. No exceptions.

```python
result.status      # "ok" | "error" | "pending_review" | "degraded" | "crisis"
result.audit_id    # "urn:aevum:audit:<uuid7>"
result.data        # function-specific payload
result.confidence  # float [0.0, 1.0]
result.provenance  # ProvenanceRecord
result.warnings    # list[str]
```

Always check `result.status` before accessing `result.data`.

## What Aevum does NOT do

- Does not move data between your systems (that is your integration layer)
- Does not run agents (agents are external; they call the five functions)
- Does not orchestrate prompts or chains (use LangChain, LlamaIndex, etc. for that)
- Does not generate compliance reports (the episodic ledger is evidence, not a report)
- Does not expose a general graph query endpoint (graph access is through `query` only)

See [NON-GOALS](https://github.com/aevum-labs/aevum/blob/main/NON-GOALS.md) for the full normative list.
