---
description: "Complete reference for ingest, query, review, commit, and replay: frozen function signatures, barrier interactions, witness validation, and outcome events."
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
- Enforce the five unconditional barriers unconditionally
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

When `capture_witness=True` (the default), the result includes
a witness snapshot in `result.data["witness"]`. This records
the sigchain state at query time. Pass this witness to `commit()`
if a human review gate separates the query from the commit — it
will detect if the underlying data changed during review.

```python
result = engine.query(
    purpose="billing-inquiry",
    subject_ids=["customer-42"],
    actor="billing-agent",
)
witness = result.data.get("witness")  # present by default

# ... human review happens here ...

commit_result = engine.commit(
    event_type="acme.billing.invoice-sent",
    payload={...},
    actor="billing-agent",
    witness=witness,          # validated before commit fires
)
# If data changed during review: status="error", error_code="stale_context"
```

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
    event_type="acme.billing.credit-issued",
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

Pass the witness from a prior `query()` call if your flow includes
a human review gate. If the data changed since the query, `commit()`
returns `status="error"` with `error_code="stale_context"` rather than
committing on stale context.

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

## Complication Outcome Events

When a complication executes an irreversible action, it should
record the real-world result by calling `commit()` with a standardised
outcome event. This closes the audit trail.

```python
engine.commit(
    event_type="action.outcome.ok",
    payload={
        "action_type": "email.send",
        "approval_audit_id": "urn:aevum:audit:...",
        "summary": "Invoice email delivered",
        "detail": {"message_id": "msg-001"},
    },
    actor="billing-complication",
)
```

Without an outcome event, the sigchain shows an approved action
with no confirmation that it succeeded. Use `replay()` to identify
approved actions that lack a subsequent outcome event.

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

`query` reads current state. `replay` reconstructs past state.

Use `query` when an agent needs context to make a decision now.
Use `replay` when an auditor needs to understand what an agent knew at
a specific moment in the past.

These are not interchangeable.

## record_capture_gap() — ordering limitation

`engine.record_capture_gap()` writes a `capture.gap` AuditEvent declaring that
an out-of-band call (LLM, tool, MCP) was made outside the complication framework.

**Important:** The gap event is written *after* the out-of-band call returns,
not before. The sigchain records the gap retroactively.

**Consequence:** If the process is interrupted between the out-of-band call and
the `record_capture_gap()` invocation, no gap event is written. An auditor
reviewing the sigchain would see no record of that call.

**Best practice:** Write the gap event *before* making the out-of-band call
where possible — declare intent, then execute. Pass `model_hint`, `reason`,
and `extra` to give auditors maximum forensic context:

```python
engine.record_capture_gap(
    gap_type="llm",
    actor="billing-agent",
    reason="direct_api_call",
    model_hint="claude-sonnet-4-6",
    extra={"endpoint": "messages", "intent": "invoice-summary"},
)
# Now make the out-of-band call
response = raw_client.messages.create(...)
```

For higher-assurance audit coverage, use the appropriate adapter complication
(e.g., `AevumAnthropicAdapter`, `AevumLangChainCallback`) rather than calling
`record_capture_gap()` manually. Adapter complications instrument the SDK at
the call site and do not have this ordering gap.

For the full threat model entry, see
[THREAT_MODEL.md — record_capture_gap() Ordering Limitation](https://github.com/aevum-labs/aevum/blob/main/THREAT_MODEL.md).
