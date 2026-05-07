---
description: "Engine method reference: all five governed functions, consent management, sigchain verification, and complication lifecycle methods."
---

# Engine Reference

`Engine` is the main entry point for all Aevum operations. It wires together
the episodic ledger, consent ledger, graph store, policy bridge, complication
registry, and the five governed functions.

```python
from aevum.core import Engine

engine = Engine()
```

---

## Five Governed Functions

### ingest()

Write data through the governed membrane into the knowledge graph.

```python
engine.ingest(
    data: dict,
    provenance: dict,
    purpose: str,
    subject_id: str,
    actor: str,
    idempotency_key: str | None = None,
    episode_id: str | None = None,
) -> OutputEnvelope
```

| Parameter | Type | Description |
|---|---|---|
| `data` | dict | The data to ingest. |
| `provenance` | dict | Must include `source_id`, `chain_of_custody`, `classification`. |
| `purpose` | str | Declared purpose for consent checking. |
| `subject_id` | str | Subject whose data is being ingested. |
| `actor` | str | Caller identity. Required, non-empty. |
| `idempotency_key` | str \| None | Optional. Prevents duplicate ingestion. |
| `episode_id` | str \| None | Optional. Groups related events into an episode. |

Barriers checked: Provenance (5), Consent (3), Crisis (1).

---

### query()

Traverse the knowledge graph for a declared purpose, subject to consent
and classification ceiling enforcement.

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

| Parameter | Type | Description |
|---|---|---|
| `purpose` | str | Declared purpose for consent checking. |
| `subject_ids` | list[str] | Subjects to query. Consent checked per subject. |
| `actor` | str | Caller identity. Required, non-empty. |
| `classification_max` | int | Data above this classification is silently redacted. Default 5 (no ceiling). |
| `constraints` | dict \| None | Optional filter applied to graph traversal. |
| `capture_witness` | bool | When True, appends a witness snapshot to `result.data["witness"]`. Default True. Set False only for read-only analytics queries that will never feed a `commit()`. |
| `episode_id` | str \| None | Optional. Groups related events into an episode. |

Barriers checked: Consent (3), Classification Ceiling (2).

The `result.data["witness"]` snapshot contains `sequence_watermark`,
`subject_ids`, `result_digest`, and `captured_at_ns`. Pass it to `commit()`
if a human review gate separates the query from the commit.

---

### review()

Present a proposed action for human decision.

```python
engine.review(
    audit_id: str,
    actor: str,
    action: str = "request",
    deadline: str | None = None,
    episode_id: str | None = None,
) -> OutputEnvelope
```

| Parameter | Type | Description |
|---|---|---|
| `audit_id` | str | URN of the review record (from the `request` call). |
| `actor` | str | Caller identity. |
| `action` | str | `"request"` \| `"approve"` \| `"veto"`. Default `"request"`. |
| `deadline` | str \| None | ISO 8601 deadline for human decision. Default veto on expiry. |
| `episode_id` | str \| None | Optional episode grouping. |

Default is veto. If the deadline passes without a human decision, the action
is blocked. This cannot be overridden by policy or complications.

---

### commit()

Append a named business event to the episodic ledger.

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

| Parameter | Type | Description |
|---|---|---|
| `event_type` | str | Application event type. Use `publisher.category.name` format. Must not use kernel-reserved prefixes. |
| `payload` | dict | Event data. Must not contain raw secrets, credentials, or PII. |
| `actor` | str | Caller identity. Required, non-empty. |
| `idempotency_key` | str \| None | Optional. Prevents duplicate commits. |
| `episode_id` | str \| None | Optional episode grouping. |
| `witness` | dict \| None | If provided, validates the witness before writing. Returns `status="error"` / `error_code="stale_context"` if context changed since the witness was captured. Pass the dict from a prior `query()` `result.data["witness"]`. |

When `witness` is provided and context has changed, `commit()` logs a
`context.stale` event to the sigchain and returns without writing the
application event. Callers must restart from `query()`.

---

### replay()

Reconstruct any past decision from the episodic ledger.

```python
engine.replay(
    audit_id: str,
    actor: str,
    scope: list[str] | None = None,
    episode_id: str | None = None,
) -> OutputEnvelope
```

| Parameter | Type | Description |
|---|---|---|
| `audit_id` | str | URN of the ledger entry to replay. |
| `actor` | str | Caller identity. Must hold a consent grant with `"replay"` in operations. |
| `scope` | list[str] \| None | Limit which fields are returned. Default: all fields. |
| `episode_id` | str \| None | Optional episode grouping. |

Returns `data["replayed_payload"]` and `data["event_metadata"]`. Deterministic:
the same `audit_id` always returns the same payload.

---

## Consent Management

### add_consent_grant()

```python
engine.add_consent_grant(grant: ConsentGrant) -> None
```

Adds an active consent grant to the consent ledger. The grant is appended
to `urn:aevum:consent` and takes effect immediately.

### revoke_consent_grant()

```python
engine.revoke_consent_grant(grant_id: str, actor: str) -> None
```

Revokes an existing consent grant. Revocation is appended to the consent
ledger; it does not modify existing entries (append-only).

---

## Sigchain Verification

### verify_sigchain()

```python
engine.verify_sigchain() -> bool
```

Verifies the full sigchain integrity: hash chain, Ed25519 signatures,
and payload hashes. Returns `True` if intact, `False` if any event fails.

### get_ledger_entries()

```python
engine.get_ledger_entries() -> list[dict]
```

Returns all events in the sigchain as a list of dicts, ordered by sequence.

### ledger_count()

```python
engine.ledger_count() -> int
```

Returns the total number of events in the sigchain.

---

## Complication Lifecycle

### install_complication()

```python
engine.install_complication(complication) -> None
```

Registers a complication. The complication enters `REGISTERED` state.
An admin must call `approve_complication()` before it can be used.

### approve_complication()

```python
engine.approve_complication(name: str, actor: str) -> None
```

Moves a complication from `REGISTERED` or `SUSPENDED` to `ACTIVE`.

### suspend_complication()

```python
engine.suspend_complication(name: str, actor: str, reason: str) -> None
```

Suspends an active complication. It may be resumed later.

### resume_complication()

```python
engine.resume_complication(name: str, actor: str) -> None
```

Resumes a suspended complication, returning it to `ACTIVE`.

### list_complications()

```python
engine.list_complications() -> list[dict]
```

Returns all registered complications with their current lifecycle state.

### complication_state()

```python
engine.complication_state(name: str) -> str
```

Returns the current lifecycle state of a named complication.

---

## Webhook Management

### register_webhook()

```python
engine.register_webhook(url: str, events: list[str], actor: str) -> str
```

Registers a webhook endpoint to receive sigchain events. Returns the webhook ID.

### deregister_webhook()

```python
engine.deregister_webhook(webhook_id: str, actor: str) -> None
```

Removes a registered webhook.
