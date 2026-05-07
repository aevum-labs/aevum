---
description: "Reference for OutputEnvelope: every field, status values, error codes, and the optional witness snapshot returned by query()."
---

# OutputEnvelope Reference

Every governed function returns exactly one `OutputEnvelope`. This is the
single contract between aevum-core and its callers. Always check `status`
before accessing `data`. The `audit_id` is always present, even on error.

---

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `status` | str | always | Outcome of the operation. See Status Values below. |
| `audit_id` | str | always | URN of the sigchain entry. Format: `urn:aevum:audit:<uuid7>`. |
| `data` | dict | always | Function-specific payload. May be empty dict `{}`. |
| `confidence` | float | always | Kernel confidence in the result. Range: [0.0, 1.0]. |
| `provenance` | ProvenanceRecord | always | Chain-of-custody for this response. |
| `warnings` | list[str] | always | Non-fatal notices (e.g. redacted subjects). May be empty. |
| `error_code` | str \| None | when error | Machine-readable error identifier. `None` when `status != "error"`. |
| `schema_version` | str | always | Always `"1.0"` in this release. |
| `witness` | dict \| None | optional | Sigchain snapshot from `query()`. See Witness Field below. |

---

## Status Values

| Status | Meaning |
|---|---|
| `"ok"` | Operation completed successfully. |
| `"error"` | Operation failed. `error_code` will be set. |
| `"pending_review"` | Blocked at a human review gate. |
| `"degraded"` | Operation completed with reduced capability. |
| `"crisis"` | Crisis content detected. Operation halted. |

Status precedence (when multiple conditions apply): `crisis` > `error` > `pending_review` > `degraded` > `ok`.

---

## Error Codes

| error_code | Meaning |
|---|---|
| `"stale_context"` | Witness validation failed at `commit()` time. Restart from `query()`. |
| `"barrier_triggered"` | An absolute barrier fired and halted the operation. |
| `"consent_missing"` | No active consent grant for the operation and subject. |
| `"provenance_missing"` | Provenance chain is incomplete. |
| `"policy_denied"` | OPA or Cedar policy denied the operation. |
| `"reserved_event_type"` | `commit()` was called with a kernel-reserved `event_type` prefix. |

---

## data Field by Function

The `data` field contents depend on which function was called:

| Function | data contents on success |
|---|---|
| `ingest` | `{}` |
| `query` | `{"results": {subject_id: ...}, "witness": {...}}` |
| `review` (request) | `{"review_id": str}` |
| `review` (resolve) | `{"review_id": str, "action": str}` |
| `commit` | `{}` |
| `replay` | `{"replayed_payload": dict, "event_metadata": dict}` |

On error, `data` may be `{}` or contain diagnostic information.

---

## Witness Field

OPTIONAL. Present only in `query()` responses when `capture_witness=True`
(the default). `None` for all other functions and when `capture_witness=False`.

The witness records the sigchain state at query time. Pass it to `commit()`
if a human review gate separates the query from the commit — it will detect
if the underlying data changed during review.

| Subfield | Type | Description |
|---|---|---|
| `sequence_watermark` | int | Highest sigchain sequence number for the queried subjects at query time. |
| `subject_ids` | list[str] | The subject IDs that were queried. |
| `result_digest` | str | SHA-256 of the canonicalised query result set. |
| `captured_at_ns` | int | Time the witness was captured, in nanoseconds since epoch. |

When `commit()` receives a witness and detects staleness, it returns
`status="error"`, `error_code="stale_context"`, and logs a `context.stale`
event to the sigchain. The caller must restart from `query()`.

Consumers that do not use witness validation should ignore this field.

---

## ProvenanceRecord Fields

The `provenance` field on every `OutputEnvelope` contains:

| Field | Type | Description |
|---|---|---|
| `source_id` | str | Data origin identifier. |
| `chain_of_custody` | list[str] | Ordered list of systems the data passed through. |
| `classification` | int | Sensitivity level (1 = public; higher = more sensitive). |

---

## Example

```python
result = engine.query(
    purpose="billing-inquiry",
    subject_ids=["customer-42"],
    actor="billing-agent",
)

assert result.status == "ok"
assert result.audit_id.startswith("urn:aevum:audit:")
assert result.schema_version == "1.0"

data = result.data["results"]["customer-42"]
witness = result.data["witness"]  # present by default

# witness subfields
watermark = witness["sequence_watermark"]  # int
digest = witness["result_digest"]           # SHA-256 hex string
```
