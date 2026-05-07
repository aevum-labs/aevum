# Section 5 — Output Envelope

Every governed function returns exactly one `OutputEnvelope`. No exceptions.
This section defines the canonical schema for all function responses.

---

## 5.1 Overview

The `OutputEnvelope` is the single contract between aevum-core and its callers.
All five functions — `ingest`, `query`, `review`, `commit`, `replay` — return
exactly this structure. Callers MUST check `status` before accessing `data`.

The `audit_id` is always present, even when `status` is `"error"`. This
guarantees every call is traceable in the sigchain regardless of outcome.

---

## 5.2 Schema

```
OutputEnvelope
├── status: str
├── audit_id: str
├── data: dict
├── confidence: float
├── provenance: ProvenanceRecord
├── warnings: list[str]
├── error_code: str | None
├── schema_version: str
└── witness: dict | None
```

### Field Definitions

**status: str**
The outcome of the operation. One of:
- `"ok"` — operation completed successfully
- `"error"` — operation failed; `error_code` will be set
- `"pending_review"` — blocked at a human review gate
- `"degraded"` — operation completed with reduced capability
- `"crisis"` — crisis content detected; operation halted

**audit_id: str**
URN of the sigchain entry for this call. Format:
`urn:aevum:audit:<uuid7>`. Always present, even on error. UUID v7 is
time-ordered; audit IDs sort chronologically.

**data: dict**
Function-specific payload. Contents vary by function:
- `ingest` — `{}` on success
- `query` — `{"results": {subject_id: ...}, "witness": {...}}`
- `review` — `{"review_id": str, "action": str}` when resolved
- `commit` — `{}` on success
- `replay` — `{"replayed_payload": dict, "event_metadata": dict}`

**confidence: float**
A float in [0.0, 1.0] indicating the kernel's confidence in the result.
1.0 for deterministic operations (ingest, commit, replay). May be lower
for query operations over sparse or partially-classified data.

**provenance: ProvenanceRecord**
Chain-of-custody record for this response. Contains `source_id`,
`chain_of_custody` (list of system identifiers), and `classification` (int).

**warnings: list[str]**
Non-fatal notices. For `query`, lists subject IDs whose data was redacted
due to classification ceiling. Never raises an error for redaction.

**error_code: str | None**
Machine-readable error identifier. Present only when `status` is `"error"`.
Reserved codes:
- `"stale_context"` — witness validation failed at `commit()` time
- `"barrier_triggered"` — an absolute barrier fired
- `"consent_missing"` — no active consent grant for the operation
- `"provenance_missing"` — provenance chain incomplete
- `"policy_denied"` — OPA or Cedar policy denied the operation

**schema_version: str**
Always `"1.0"` in this release. Used to detect schema evolution in
multi-version deployments. MUST be validated by consumers before parsing.

**witness: dict | None**
OPTIONAL. Present when `query()` is called with `capture_witness=True`.
Contains a snapshot of the sigchain state at query time, used
to detect stale context at `commit()` time.

Fields:
- `sequence_watermark: int`
  Highest sequence number in the sigchain for the queried
  subjects at the moment the query completed.
- `subject_ids: list[str]`
  The subject IDs that were queried.
- `result_digest: str`
  SHA-256 of the canonicalised query result set.
- `captured_at_ns: int`
  Time the witness was captured, in nanoseconds since epoch.

MUST be `None` for `ingest`, `review`, `commit`, and `replay` responses.
Consumers that do not use witness validation MUST ignore this field.

---

## 5.3 Status Precedence

When multiple conditions apply simultaneously, the highest-severity status
wins. Severity order (highest to lowest):

1. `"crisis"` — always trumps all other outcomes
2. `"error"` — barrier or policy failure
3. `"pending_review"` — blocked at human gate
4. `"degraded"` — partial success
5. `"ok"` — full success

---

## 5.4 Mandatory Fields

The following fields MUST always be present and non-null regardless of
`status`. Implementations that omit any mandatory field are non-conformant.

- `status`
- `audit_id`
- `data` (may be empty dict `{}`)
- `confidence`
- `provenance`
- `warnings` (may be empty list `[]`)
- `schema_version`

The `error_code` field MUST be `None` when `status` is not `"error"`.
The `witness` field MUST be `None` when the function is not `query()` or
when `capture_witness=False` was passed.

---

## 5.5 ProvenanceRecord Schema

```
ProvenanceRecord
├── source_id: str
├── chain_of_custody: list[str]
└── classification: int
```

`source_id` identifies the data origin. `chain_of_custody` is an ordered
list of system identifiers through which the data passed before reaching
aevum-core. `classification` is an integer sensitivity level (1 = public,
higher = more sensitive). The classification ceiling barrier (Barrier 2)
enforces that agents cannot query data above their declared `classification_max`.
