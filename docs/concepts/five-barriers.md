---
description: "Five hardcoded, non-configurable barriers: crisis detection, classification ceiling, consent enforcement, audit immutability, and provenance checks."
---

# The Five Absolute Barriers

Absolute barriers are unconditional, hardcoded checks in `aevum-core`.
They are not policies. They are not configurable. They cannot be bypassed.

## What makes a barrier different from a policy

| | Absolute barrier | Policy (OPA / Cedar) |
|---|---|---|
| Location | `barriers.py` — hardcoded | OPA sidecar or cedarpy |
| Configurable | Never | Yes |
| Bypassable | Never | Via policy rules |
| Fires even without Cedar | Yes | No (falls back to permissive) |
| Audited | Yes — every check is logged | Yes |

If you need a check that can be tuned per environment, use Cedar or OPA.
If you need a check that must never be overridden, it belongs in `barriers.py`.

## Barrier 1 — Crisis Detection

**Applies to:** `ingest`

**Behavior:** If the payload contains any crisis keyword (suicidal ideation,
immediate physical danger, medical emergency), the operation is halted immediately
and a `crisis` envelope is returned with safe messaging and crisis resources.

```python
result = engine.ingest(
    data={"message": "I want to kill myself"},
    provenance={"source_id": "chat", "chain_of_custody": ["chat"], "classification": 0},
    purpose="support",
    subject_id="user-1",
    actor="support-agent",
)

result.status  # "crisis"
result.data["safe_message"]  # "It sounds like you or someone you know..."
result.data["resources"]     # ["988 Suicide & Crisis Lifeline: ...", ...]
```

The operation is not ingested. No data reaches the knowledge graph.
The crisis event is logged to the episodic ledger.

**Keywords include:** "kill myself", "end my life", "want to die",
"commit suicide", "hurt someone", "heart attack", "can't breathe",
"overdose", "going to shoot", "going to stab", and others.

!!! warning
    The crisis barrier is a first-line safety net, not a complete mental health
    intervention. If your application serves vulnerable users, complement this
    with human review and additional clinical safety measures.

## Barrier 2 — Classification Ceiling

**Applies to:** `query`

**Behavior:** Results whose classification level exceeds `classification_max`
are silently redacted from the response. The operation is not errored — the
caller simply does not receive above-clearance data.

```python
result = engine.query(
    purpose="billing-inquiry",
    subject_ids=["user-1"],
    actor="low-clearance-agent",
    classification_max=1,  # can only see classification 0 and 1
)

result.status    # "ok"
result.warnings  # ["user-1: redacted (classification 2 > ceiling 1)"]
result.data["results"].get("user-1")  # None — redacted
```

Classification levels:

| Level | Typical use |
|---|---|
| 0 | Public / de-identified |
| 1 | Internal / limited |
| 2 | Confidential / identified PII |
| 3 | Highly sensitive (PHI, financial, legal) |

## Barrier 3 — Consent

**Applies to:** `ingest`, `query`, `replay`

**Behavior:** If the actor does not hold an active consent grant authorizing
the operation on the specified subject, the operation is blocked and an error
envelope is returned.

```python
# No consent grant added — this will fail
result = engine.ingest(
    data={"note": "test"},
    provenance={"source_id": "test", "chain_of_custody": ["test"], "classification": 0},
    purpose="testing",
    subject_id="user-1",
    actor="my-agent",
)

result.status                    # "error"
result.data["error_code"]        # "consent_required"
result.data["error_detail"]      # "No active consent grant for operation 'ingest'..."
```

This is the consent fast-path denial. Even without Cedar installed, this check fires.

A consent grant must specify:
- `subject_id` — whose data is covered
- `grantee_id` — which agent is covered
- `operations` — which operations are permitted (`["ingest", "query", "replay", "export"]`)
- `purpose` — must be specific (not "any" or "all")
- `classification_max` — ceiling for this grant
- `expires_at` — grants do not last forever

## Barrier 4 — Audit Immutability

**Applies to:** All operations (enforced by the ledger, not checked at call time)

**Behavior:** The episodic ledger is append-only. No entry can be modified or
deleted after it is written. The ledger raises an error if any code attempts
to overwrite or remove an entry.

This is enforced structurally — `InMemoryLedger` (and all persistent backends)
raise `ImmutabilityError` on any write to an existing entry.

Verify the chain at any time:

```python
intact = engine.verify_sigchain()
# True = all entries are valid and unmodified
# False = tampering detected or key rotation issue
```

## Barrier 5 — Provenance

**Applies to:** `ingest`

**Behavior:** Every `ingest` call must include a provenance record with a
non-empty `source_id`. If provenance is missing or incomplete, the operation
is blocked.

```python
# Missing provenance — this will fail
result = engine.ingest(
    data={"note": "test"},
    provenance={},  # no source_id
    purpose="testing",
    subject_id="user-1",
    actor="my-agent",
)

result.status              # "error"
result.data["error_code"]  # "provenance_required"
```

The provenance record becomes part of the signed audit event. You can always
trace back to the original source of any piece of data in the knowledge graph.

## Testing the barriers

The canary tests in `packages/aevum-core/tests/test_canary.py` verify all
five barriers unconditionally. Run them with:

```bash
uv run pytest packages/aevum-core/tests/test_canary.py -v
```

These tests must always pass. If they fail, a core invariant has been violated.
The CI pipeline runs them on every pull request that touches `aevum-core`.
