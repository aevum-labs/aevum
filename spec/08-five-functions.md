# Section 8 — The Five Governed Functions

The five public functions are the complete API surface of aevum-core.
Their signatures and behavioral contracts are frozen at Phase 1.

---

## 8.1 Overview

| Function | Internal verb | Role |
|---|---|---|
| `ingest` | RELATE | Write data through the governed membrane |
| `query` | NAVIGATE | Traverse the graph for a declared purpose |
| `review` | GOVERN | Present context for human decision |
| `commit` | REMEMBER | Append event to the episodic ledger |
| `replay` | REPLAY | Reconstruct any past decision faithfully |

---

## 8.2 Common Contract

All five functions:

1. Accept an `actor: str` parameter (non-empty; identifies the caller)
2. Return exactly one `OutputEnvelope` (Section 5)
3. Append exactly one `AuditEvent` to the episodic ledger (Section 6)
4. Enforce all five absolute barriers unconditionally (Section 7)
5. Accept an optional `idempotency_key: str` for at-most-once semantics

The five functions MUST NOT be called from within a complication's
`execute()` method directly. Complications receive a restricted kernel
proxy that enforces separation of privilege.

---

## 8.3 ingest — RELATE

Write data through the governed membrane into the knowledge graph.

### Signature

```python
engine.ingest(
    data: dict,
    provenance: dict,       # source_id, chain_of_custody, classification
    purpose: str,
    subject_id: str,
    actor: str,
    idempotency_key: str | None = None,
    episode_id: str | None = None,
) -> OutputEnvelope
```

### Preconditions

1. `provenance.source_id` MUST be present and non-empty (Barrier 5)
2. The `actor` MUST hold an active consent grant for `ingest` on `subject_id` (Barrier 3)
3. The payload MUST pass crisis screening (Barrier 1)

### Postconditions

1. Data is written to `urn:aevum:knowledge`
2. An `AuditEvent` of type `ingest.accepted` is appended to `urn:aevum:provenance`
3. The returned `OutputEnvelope.data` is `{}` on success

### Naming

Never say "write", "insert", "store", or "index". Say `ingest`.

---

## 8.4 query — NAVIGATE

Traverse the knowledge graph for a declared purpose, subject to consent
and classification ceiling enforcement.

### Signature

```python
engine.query(
    purpose: str,
    subject_ids: list[str],
    actor: str,
    classification_max: int = 5,
    constraints: dict | None = None,
    capture_witness: bool = True,
    episode_id: str | None = None,
) -> OutputEnvelope
```

### Preconditions

1. The `actor` MUST hold an active consent grant for `query` on each `subject_id` (Barrier 3)
2. `classification_max` MUST be respected; data above this level is silently redacted

### Postconditions

1. The returned `OutputEnvelope.data["results"]` is a dict keyed by subject ID
2. Subject IDs whose data was fully redacted appear in `OutputEnvelope.warnings`
3. If `capture_witness` is `True` (default), the returned `OutputEnvelope`
   data field contains a `"witness"` key with a Witness snapshot:
   - `sequence_watermark` (int): highest sigchain sequence for queried subjects
   - `subject_ids` (list[str]): the subject IDs that were queried
   - `result_digest` (str, SHA-256): digest of the canonicalised result set
   - `captured_at_ns` (int): capture time in nanoseconds since epoch

   The witness records the sigchain state at query time and enables stale-context
   detection at `commit()` time. See Section 8.5.

### Naming

Never say "search", "fetch", "retrieve", or "navigate". Say `query`.

---

## 8.5 commit — REMEMBER

Append a named business event to the episodic ledger.

### Signature

```python
engine.commit(
    event_type: str,
    payload: dict,
    actor: str,
    idempotency_key: str | None = None,
    episode_id: str | None = None,
    witness: dict | None = None,
) -> OutputEnvelope
```

### Preconditions

1. `event_type` MUST follow the format `<publisher>.<category>.<name>` or use
   a kernel-reserved prefix listed in Section 8.7
2. `actor` MUST be non-empty
3. `payload` MUST NOT contain raw secrets, credentials, or PII

### Optional precondition (witness validation)

If a `witness` dict is provided, the implementation MUST call `revalidate()`
before any ledger write. If `revalidate()` detects staleness, the implementation
MUST:
- Return an `OutputEnvelope` with `status="error"` and `error_code="stale_context"`
- Append a `context.stale` event to the ledger recording the drift

This protects the `query`→`review`→`commit` flow against data mutations
during the human review window. The caller MUST restart from `query()` with
fresh context when `stale_context` is returned.

### Postconditions

1. An `AuditEvent` with the given `event_type` is appended to `urn:aevum:provenance`
2. The returned `OutputEnvelope.data` is `{}` on success

### Naming

Never say "save", "persist", "log", or "record". Say `commit`.

---

## 8.6 review — GOVERN

Present a proposed action for human decision. The operation is blocked
until approved or vetoed.

### Signature

```python
engine.review(
    audit_id: str,
    actor: str,
    action: str = "request",   # "request" | "approve" | "veto"
    deadline: str | None = None,
    episode_id: str | None = None,
) -> OutputEnvelope
```

### Preconditions

1. When `action="approve"` or `action="veto"`, the `audit_id` MUST reference
   an existing pending review record
2. The `actor` performing the approval or veto MUST be a human actor
   (enforced by policy; non-human actors cannot approve reviews)

### Postconditions

1. When `action="request"`: returns `status="pending_review"` and creates a
   pending review record
2. When `action="approve"`: returns `status="ok"` and records `review.approved`
3. When `action="veto"` or deadline passes without decision: returns
   `status="error"` and records `review.vetoed`

**Default is veto.** If a deadline passes without a human decision, the
action is blocked. This is an absolute invariant — it cannot be overridden
by policy or by a complication.

### Naming

Never say "checkpoint", "approve" (as the function name), or "authorize".
Say `review`.

---

## 8.7 Reserved Event Type Prefixes

The following `event_type` prefixes are reserved by the kernel and
MUST NOT be used in application-level `commit()` calls:

| Prefix | Owner |
|---|---|
| `ingest.*` | kernel ingest events |
| `context.*` | kernel context management events |
| `barrier.*` | kernel barrier events |
| `complication.*` | kernel complication lifecycle events |
| `review.*` | kernel review events |
| `session.*` | kernel session events |
| `replay.*` | kernel replay events |

The following prefix is reserved for complication outcome events
(see Section 11.6):

| Prefix | Purpose |
|---|---|
| `action.outcome.*` | complication real-world outcome records |

Registered outcome event types:
- `action.outcome.ok` — action completed successfully
- `action.outcome.failed` — action was attempted and failed
- `action.outcome.partial` — action partially completed

**Kernel-written event types** (implementations MUST use exactly these strings):

| Event type | When written |
|---|---|
| `ingest.accepted` | Successful ingest through the governed membrane |
| `ingest.rejected` | Ingest denied by policy or consent |
| `query.accepted` | Graph traversal executed |
| `review.created` | Review gate opened |
| `review.approved` | Human approved a pending review |
| `review.vetoed` | Human vetoed (or deadline passed) |
| `commit.accepted` | Manual commit appended |
| `replay.started` | Replay of a past decision begun |
| `barrier.triggered` | Any absolute barrier fired |
| `complication.installed` | Complication registered |
| `complication.approved` | Complication moved to ACTIVE |
| `complication.suspended` | Complication suspended by admin |
| `context.stale` | `commit()` rejected stale witness |
| `session.start` | Kernel startup |

**Application event types** MUST use a namespaced prefix:

    <publisher>.<category>.<name>   e.g. "acme.billing.invoice-sent"

Application code MUST NOT use any of the reserved prefixes listed above.
Violations are rejected at `commit()` with `error_code="reserved_event_type"`.

---

## 8.8 replay — REPLAY

Reconstruct any past decision from the episodic ledger.

### Signature

```python
engine.replay(
    audit_id: str,
    actor: str,
    scope: list[str] | None = None,
    episode_id: str | None = None,
) -> OutputEnvelope
```

### Preconditions

1. The `actor` MUST hold an active consent grant with `"replay"` in operations (Barrier 3)
2. The `audit_id` MUST reference an existing ledger entry

### Postconditions

1. The returned `OutputEnvelope.data["replayed_payload"]` is the original event payload
2. The returned `OutputEnvelope.data["event_metadata"]` contains the original
   `event_type`, `actor`, `system_time`, `valid_from`, `sequence`
3. If `scope` is provided, only those fields are returned

**Deterministic guarantee:** The same `audit_id` MUST always return the same
payload, regardless of when or by whom `replay()` is called. This invariant is
frozen at Phase 1 and cannot be changed.

### Naming

Never say "explain", "audit", or "reconstruct". Say `replay`.
