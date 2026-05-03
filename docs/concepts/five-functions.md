---
description: "Complete API reference for ingest, query, review, commit, and replay: frozen function signatures, barrier interactions, and HTTP endpoints."
---

# The Five Functions

These are the complete public API of `aevum-core`. Their signatures and
behavioral contracts are frozen at Phase 1.

## Overview

| Function | Internal verb | What it does |
|---|---|---|
| `ingest` | RELATE | Write data through the governed membrane |
| `query` | NAVIGATE | Traverse the graph for a declared purpose |
| `review` | GOVERN | Present context for human decision |
| `commit` | REMEMBER | Append a named event to the episodic ledger |
| `replay` | (REPLAY) | Reconstruct any past decision faithfully |

All five functions:
- Return exactly one `OutputEnvelope`
- Write to the episodic ledger (every call is audited)
- Enforce the five absolute barriers unconditionally
- Require an `actor` parameter identifying the caller

## ingest — RELATE

Write data through the governed membrane into the knowledge graph.

```python
result = engine.ingest(
    data={"invoice_id": "INV-001", "amount": 1500.00, "status": "paid"},
    provenance={
        "source_id": "billing-system",
        "chain_of_custody": ["billing-system"],
        "classification": 1,
    },
    purpose="billing-inquiry",
    subject_id="customer-42",
    actor="billing-agent",
    idempotency_key="INV-001-ingest",  # optional
)
```

**Barriers checked:** Provenance (5), Consent (3), Crisis (1)

**Returns:** `OutputEnvelope` with `data={}` on success, `audit_id` always set.

**Naming:** Never say "write", "insert", "store", or "index". Say `ingest`.

## query — NAVIGATE

Read context from the knowledge graph for a declared purpose.

```python
result = engine.query(
    purpose="billing-inquiry",
    subject_ids=["customer-42"],
    actor="billing-agent",
    classification_max=1,   # redact anything classified higher than 1
    constraints={"type": "invoice"},  # optional filter
)

if result.status == "ok":
    data = result.data["results"]["customer-42"]
```

**Barriers checked:** Consent (3), Classification Ceiling (2)

**Returns:** `OutputEnvelope` with `data={"results": {subject_id: ...}}`.

Results above `classification_max` are silently redacted (not errored).
The `warnings` field lists redacted subject IDs.

**Naming:** Never say "search", "fetch", "retrieve", or "navigate". Say `query`.

## review — GOVERN

Present a proposed action for human decision. Blocks until approved or vetoed.

```python
# Agent requests a review gate
result = engine.review(
    audit_id="urn:aevum:audit:...",
    actor="billing-agent",
)
# status="pending_review" — operation is blocked

# Human approves
engine.review(
    audit_id="urn:aevum:audit:...",
    actor="billing-manager",
    action="approve",
)
# status="ok"

# Human vetoes
engine.review(
    audit_id="urn:aevum:audit:...",
    actor="billing-manager",
    action="veto",
)
# status="error"
```

**Default is veto.** If a deadline passes without a human decision, the action is blocked.

**Naming:** Never say "checkpoint", "approve" (as the function name), or "authorize". Say `review`.

## commit — REMEMBER

Append a named business event to the episodic ledger.

```python
result = engine.commit(
    event_type="credit.issued",
    payload={
        "invoice_id": "INV-001",
        "credit_amount": 150.00,
        "reason": "billing-error",
    },
    actor="billing-agent",
    idempotency_key="credit-INV-001",  # optional
)
```

**No barriers beyond provenance.** `commit` does not check consent — it is
used to record outcomes of already-approved operations.

**Returns:** `OutputEnvelope` with `data={}`, `audit_id` set.

**Naming:** Never say "save", "persist", "log", or "record". Say `commit`.

## replay — REPLAY

Reconstruct any past decision from the episodic ledger.

```python
result = engine.replay(
    audit_id="urn:aevum:audit:0196...",
    actor="audit-agent",
    scope=["payload"],  # optional — limit what is returned
)

if result.status == "ok":
    original = result.data["replayed_payload"]
    metadata = result.data["event_metadata"]
```

**Barriers checked:** Consent (3) — the actor must hold a grant with `"replay"` in operations.

**Deterministic:** The same `audit_id` always returns the same payload, regardless
of when it is called. This is the guarantee.

**Naming:** Never say "explain", "audit", or "reconstruct". Say `replay`.

## The HTTP surface

When `aevum-server` is installed, the five functions are available over HTTP:

| Endpoint | Function |
|---|---|
| `POST /ingest` | `engine.ingest()` |
| `POST /query` | `engine.query()` |
| `POST /review` | `engine.review()` |
| `POST /commit` | `engine.commit()` |
| `POST /replay` | `engine.replay()` |

The request and response bodies are JSON representations of the Python arguments
and `OutputEnvelope` respectively.

## replay vs query — the distinction that matters

These two functions are often confused:

| | `query` | `replay` |
|---|---|---|
| Reads from | `urn:aevum:knowledge` (current state) | `urn:aevum:provenance` (immutable history) |
| Returns | Current entities matching criteria | Exact payload from a specific past event |
| Changes with new data | Yes | Never |
| Requires specific ID | No | Yes (`audit_id`) |
| Use for | "What does my agent know now?" | "What did my agent see at decision time?" |

Use `query` when you want current context.
Use `replay` when you need to reconstruct a specific past decision exactly as it occurred.
