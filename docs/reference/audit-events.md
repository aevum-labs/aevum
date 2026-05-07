---
description: "Reference for all Aevum sigchain event types: kernel-reserved events, complication outcome events, and their payload fields."
---

# Audit Event Reference

Every call to a governed function appends exactly one `AuditEvent` to the
sigchain (`urn:aevum:provenance`). This page documents all kernel-reserved
event types and their payload fields.

Application code MUST NOT use kernel-reserved event type prefixes.
Application events must use a namespaced prefix: `publisher.category.name`.

---

## Kernel Event Types

### session.start

Kernel startup. Always sequence 1 in a new chain.

| Field | Type | Description |
|---|---|---|
| `capture_surface` | dict | `{"llm": bool, "mcp": bool}` — active capture surfaces |
| `key_provenance` | str | How the signing key was provisioned |

`key_provenance` values: `in-process`, `external`, `vault-transit`, `aws-kms`, `pkcs11`.

---

### ingest.accepted

Data was successfully ingested through the governed membrane.

| Field | Type | Description |
|---|---|---|
| `subject_id` | str | The subject whose data was ingested |
| `purpose` | str | The declared purpose |
| `classification` | int | Classification level of the ingested data |
| `source_id` | str | Data origin identifier |
| `idempotency_key` | str \| None | Provided idempotency key, if any |

---

### ingest.rejected

Ingest was denied by policy, consent, or a barrier.

| Field | Type | Description |
|---|---|---|
| `subject_id` | str | The subject whose data was rejected |
| `reason` | str | Why the ingest was rejected |
| `barrier` | int \| None | Barrier number that fired, if applicable |

---

### query.accepted

A graph traversal was executed.

| Field | Type | Description |
|---|---|---|
| `purpose` | str | The declared purpose |
| `subject_ids` | list[str] | Subjects queried |
| `classification_max` | int | Maximum classification ceiling applied |
| `redacted_count` | int | Number of subjects whose data was redacted |
| `witness_captured` | bool | Whether a witness snapshot was captured |

---

### review.created

A human review gate was opened by `engine.review()`.

| Field | Type | Description |
|---|---|---|
| `requested_by` | str | Actor who requested the review |
| `deadline` | str \| None | ISO 8601 deadline, if set |

---

### review.approved

A human approved a pending review.

| Field | Type | Description |
|---|---|---|
| `approved_by` | str | Actor who approved |
| `original_audit_id` | str | audit_id of the review.created event |

---

### review.vetoed

A human vetoed a pending review, or the deadline passed.

| Field | Type | Description |
|---|---|---|
| `vetoed_by` | str \| None | Actor who vetoed (None if deadline expired) |
| `reason` | str | `"explicit_veto"` or `"deadline_expired"` |
| `original_audit_id` | str | audit_id of the review.created event |

---

### commit.accepted

A named business event was appended to the ledger.

| Field | Type | Description |
|---|---|---|
| `event_type` | str | The application event type committed |
| `idempotency_key` | str \| None | Provided idempotency key, if any |
| `witness_validated` | bool | Whether a witness was checked before writing |

---

### replay.started

A past decision is being deterministically reconstructed.

| Field | Type | Description |
|---|---|---|
| `target_audit_id` | str | audit_id of the event being replayed |
| `scope` | list[str] \| None | Fields requested, if scoped |

---

### barrier.triggered

An absolute barrier fired and halted the operation.

| Field | Type | Description |
|---|---|---|
| `barrier_number` | int | Which barrier fired (1–5) |
| `barrier_name` | str | Human-readable name |
| `operation` | str | Which function was blocked |
| `reason` | str | Why the barrier fired |

---

### complication.installed

A complication was registered with the kernel.

| Field | Type | Description |
|---|---|---|
| `name` | str | Complication name |
| `version` | str | Complication version |
| `actor_id` | str | Complication actor identity |

---

### complication.approved

A complication was approved and moved to ACTIVE state.

| Field | Type | Description |
|---|---|---|
| `name` | str | Complication name |
| `approved_by` | str | Admin actor who approved |

---

### complication.suspended

A complication was suspended by an admin.

| Field | Type | Description |
|---|---|---|
| `name` | str | Complication name |
| `suspended_by` | str | Admin actor who suspended |
| `reason` | str | Why the complication was suspended |

---

### context.stale

`commit()` rejected a stale witness. The data queried by the caller has
changed since the witness was captured. The commit was not written.

| Field | Type | Description |
|---|---|---|
| `reason` | str | Human-readable description of what changed |
| `old_watermark` | int | Sigchain sequence number at witness capture time |
| `new_watermark` | int | Sigchain sequence number at commit time |
| `subject_ids` | list[str] | The subjects whose data changed |

Callers receiving `stale_context` MUST restart from `query()` with fresh context.

---

## Complication Outcome Event Types

Complications that execute irreversible external actions SHOULD record the
real-world result using one of these event types. See Section 11.6 of the
specification for the full obligation.

The `action.outcome.*` prefix is reserved for complication use. Kernel code
does not write these events — they are written by complications via `commit()`.

### action.outcome.ok

The external action completed successfully.

| Field | Type | Description |
|---|---|---|
| `action_type` | str | Human-readable name of the action (e.g. `"email.send"`) |
| `approval_audit_id` | str | audit_id of the review event that authorised this action |
| `summary` | str | One-sentence description of what happened |
| `detail` | dict | Complication-defined structured detail |

`detail` MUST NOT include raw secrets, credentials, or PII.

### action.outcome.failed

The external action was attempted but failed.

| Field | Type | Description |
|---|---|---|
| `action_type` | str | Human-readable name of the action |
| `approval_audit_id` | str | audit_id of the authorising review event |
| `summary` | str | One-sentence description of the failure |
| `detail` | dict | MUST include `"error": str` describing the failure |

### action.outcome.partial

The external action partially completed. Use sparingly — prefer
`action.outcome.ok` or `action.outcome.failed` with detail instead.

| Field | Type | Description |
|---|---|---|
| `action_type` | str | Human-readable name of the action |
| `approval_audit_id` | str | audit_id of the authorising review event |
| `summary` | str | One-sentence description of what partially completed |
| `detail` | dict | Complication-defined; describe what succeeded and what failed |

---

## Finding Approved Actions Without Outcomes

Use `replay()` to identify review approvals that have no subsequent
`action.outcome.*` event. This detects compliance gaps where a complication
executed an action but did not record the real-world result:

```python
# Replay a review.approved event and check if an outcome follows
result = engine.replay(
    audit_id="urn:aevum:audit:...",
    actor="audit-agent",
)
# Examine result.data["event_metadata"]["event_type"]
# Then search for action.outcome.* events with matching approval_audit_id
```
