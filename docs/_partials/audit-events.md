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
| `fact_id` | str \| omitted | Fact identifier when a typed fact was created |

> **Ingest rejections** do not emit `ingest.rejected`. Barrier violations surface
> as `barrier.triggered` events. See [`barrier.triggered`](#barriertriggered).

---

### query.complete

A graph traversal completed successfully.

| Field | Type | Description |
|---|---|---|
| `subject_ids` | list[str] | Subjects queried |
| `purpose` | str | The declared purpose |
| `result_count` | int | Number of graph results returned |
| `redacted_count` | int | Number of subjects whose data was redacted (legacy; always `0` post-B2 — classification ceiling now blocks the whole query rather than redacting individual subjects) |
| `complication_results` | dict | Per-complication output keyed by complication name |
| `uncertainty` | float | Uncertainty score from the assembled ContextBundle |
| `completeness` | str | Completeness assessment from the assembled ContextBundle |

---

### replay.complete

A past decision's signed record was retrieved and verified.

| Field | Type | Description |
|---|---|---|
| `original_audit_id` | str | `audit_id` of the event that was replayed |
| `original_event_type` | str | Event type of the original ledger entry |
| `replayed_by` | str | Actor who initiated the replay |

---

### review.created

A human review gate was opened by `engine.create_review()`.

| Field | Type | Description |
|---|---|---|
| `audit_id` | str | Provisional audit ID of the pending review |
| `proposed_action` | str | The action awaiting human decision |
| `reason` | str | Why human review was requested |
| `autonomy_level` | int | Autonomy level at the time of the review request |

---

### review.approved

A human approved a pending review.

| Field | Type | Description |
|---|---|---|
| `original_audit_id` | str | `audit_id` of the `review.created` event |
| `approved_by` | str | Actor who approved |

---

### review.vetoed

A human vetoed a pending review, or the review deadline elapsed with no
response (veto-as-default).

This event has two payload shapes depending on the veto path:

**Explicit veto** (`review(action="veto")`):

| Field | Type | Description |
|---|---|---|
| `original_audit_id` | str | `audit_id` of the `review.created` event |
| `vetoed_by` | str | Actor who issued the explicit veto |

**Deadline elapsed** (veto-as-default):

| Field | Type | Description |
|---|---|---|
| `original_audit_id` | str | `audit_id` of the `review.created` event |
| `reason` | str | Always `"veto_as_default_deadline_elapsed"` |

---

### app.event

Application events committed through the `commit()` (REMEMBER) function. The
event type is caller-defined and written directly to the ledger under the
caller-provided name. The payload is opaque to the kernel — fields are
application-defined.

Application event types MUST NOT begin with any kernel-reserved prefix:
`ingest.`, `query.`, `review.`, `commit.`, `replay.`, `barrier.`, `policy.`,
`agent.`.

There are no kernel-mandated payload fields for application events. The
application is responsible for including any fields required for replay
fidelity.

See [`commit.rejected`](#commitrejected) for the failure path when a reserved
prefix is used.

---

### commit.rejected

A `commit()` call was rejected because the caller-provided `event_type`
begins with a kernel-reserved prefix.

| Field | Type | Description |
|---|---|---|
| `reason` | str | Always `"reserved_event_type"` |
| `event_type` | str | The rejected event type string |

The commit was not written to the ledger.

---

### barrier.triggered

An unconditional barrier fired and halted the operation. Always accompanies
an error `OutputEnvelope` — the operation did not complete.

| Field | Type | Description |
|---|---|---|
| `barrier` | int | Which barrier fired (1–5) |
| `function` | str | Which governed function was blocked: `"ingest"`, `"query"`, or `"commit"` |
| `reason` | str \| omitted | Why the barrier fired; present when applicable: `"policy_deny"` (ABAC denial) or `"classification_ceiling"` (data above clearance) |
| `subject_id` | str \| omitted | The consenting subject; present only when barrier 3 (consent) fires |
| `above_ceiling` | list[str] \| omitted | Subject IDs that exceeded the clearance ceiling; present only when `reason` is `"classification_ceiling"` |

Barrier numbers map to unconditional barriers: 1 = Crisis, 2 = ABAC/Classification,
3 = Consent, 5 = Provenance. See `aevum.core.barriers` for the normative definitions.

---

### capture.gap

A capture gap was recorded, indicating that a portion of context was not
captured (e.g. an LLM turn occurred outside Aevum's observation window).

| Field | Type | Description |
|---|---|---|
| `gap_type` | str | Classification of the gap (e.g. `"llm_turn"`, `"tool_call"`) |
| `reason` | str | Human-readable explanation; defaults to `"unspecified"` |
| `model_hint` | str \| omitted | Model identifier hint, when known |
| `extra` | dict \| omitted | Additional complication-defined context |

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

### session.committed

A session batch was committed to the kernel sigchain. Written directly to the
sigchain (not via the normal audit ledger path) when a `SessionRecord` is
finalised.

| Field | Type | Description |
|---|---|---|
| `session_id` | str | Identifier of the committed session |
| `commit_type` | str | Commit type value from the `CommitType` enum |
| `merkle_root` | str | Merkle root of the session's event set |
| `event_count` | int | Number of events included in the session batch |

---

### complication.installed

A complication was registered with the kernel.

| Field | Type | Description |
|---|---|---|
| `name` | str | Complication name |
| `version` | str | Complication version |
| `actor_id` | str | Complication actor identity (manifest `actor_id` if present, else `name`) |

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
| `reason` | str | Why the complication was suspended (empty string if unspecified; field always present) |

---

### complication.resumed

A suspended complication was resumed by an admin (SUSPENDED → ACTIVE).

| Field | Type | Description |
|---|---|---|
| `name` | str | Complication name |
| `resumed_by` | str | Admin actor who resumed |

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
