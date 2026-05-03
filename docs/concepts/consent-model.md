---
description: "Consent as an absolute barrier: OR-Set CRDT grants, purpose-scoped operations, classification ceiling, GDPR Article 7 support, and immediate revocation."
---

# Consent Model

Consent in Aevum is not a policy setting — it is a barrier. No traversal
without consent; no ingestion without consent. This is unconditional.

## Why consent is a barrier, not a policy

Policies can be relaxed. Barriers cannot.

If consent were a Cedar or OPA policy, an administrator could write a rule
that bypasses it. In Aevum, consent enforcement is hardcoded in `barriers.py`
and fires before any policy evaluation. Even with Cedar not installed,
the consent fast-path denial fires.

The design intention: an AI agent must never be able to access data about a
person without that person's active, specific consent — even if the operator
misconfigures their policies.

## Consent grant fields

```python
from aevum.core.consent.models import ConsentGrant

grant = ConsentGrant(
    grant_id="grant-001",           # unique ID for this grant
    subject_id="customer-42",       # whose data is covered
    grantee_id="billing-agent",     # which agent is covered
    operations=["ingest", "query"], # permitted operations
    purpose="billing-inquiry",      # must be specific
    classification_max=1,           # ceiling: 0=public, 1=internal, 2=PII, 3=sensitive
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
    authorization_ref="customer-consent-form-2026-01-01",  # optional reference
)

engine.add_consent_grant(grant)
```

**Valid operations:** `"ingest"`, `"query"`, `"replay"`, `"export"`

Note: `"review"` and `"commit"` do not require consent grants — they record
outcomes of already-consented operations.

## The OR-Set CRDT — immediate revocation

Aevum's consent ledger is modeled as an OR-Set (Observed-Remove Set) CRDT.
This has one critical property: **revocation is immediate**.

When you call `engine.revoke_consent_grant(grant_id)`:

1. The grant is marked revoked in the consent ledger
2. Every subsequent operation that checks for this grant will see it as inactive
3. The revocation is itself an append-only ledger entry — it cannot be undone
   (you can add a new grant if needed)

```python
engine.revoke_consent_grant("grant-001")

# Subsequent ingest by billing-agent for customer-42 is now blocked
result = engine.ingest(
    data={"note": "test"},
    provenance={"source_id": "billing", "chain_of_custody": ["billing"], "classification": 0},
    purpose="billing-inquiry",
    subject_id="customer-42",
    actor="billing-agent",
)
result.status              # "error"
result.data["error_code"]  # "consent_required"
```

This enables GDPR-style immediate revocation. The data remains in the
knowledge graph (audit immutability: Barrier 4), but it is unreachable
for any operation by any grantee until a new grant is added.

## Purpose must be specific

The `purpose` field must be specific and auditable. The kernel rejects
generic purposes:

```python
# These raise ValidationError:
ConsentGrant(..., purpose="any")
ConsentGrant(..., purpose="all purposes")
ConsentGrant(..., purpose="")

# These are valid:
ConsentGrant(..., purpose="billing-inquiry")
ConsentGrant(..., purpose="care-coordination")
ConsentGrant(..., purpose="fraud-detection")
```

Purpose must match between the grant and the operation:

```python
# Grant for "billing-inquiry" only
engine.add_consent_grant(ConsentGrant(
    ..., purpose="billing-inquiry", ...
))

# This fails — purpose does not match
engine.ingest(
    ..., purpose="fraud-detection", ...
)
# status="error", error_code="consent_required"
```

## The operations list

| Operation | What it gates |
|---|---|
| `"ingest"` | Writing data through the governed membrane |
| `"query"` | Reading context from the knowledge graph |
| `"replay"` | Reconstructing past decisions from the episodic ledger |
| `"export"` | Exporting data out of Aevum (future) |

A single grant can cover multiple operations:

```python
# Agent can ingest and query but not replay
ConsentGrant(..., operations=["ingest", "query"], ...)

# Audit agent can only replay
ConsentGrant(..., operations=["replay"], ...)
```

## Classification ceiling in grants

The `classification_max` in a consent grant sets the ceiling for what the
grantee can see. This interacts with Barrier 2 (Classification Ceiling):

- Data ingested at classification 2
- Grant has `classification_max=1`
- The grantee's query returns no results for that data (redacted by Barrier 2)

This means you can grant an agent consent to query data for a subject,
while still preventing it from seeing highly classified data about that subject.

## Consent and GDPR

Aevum's consent model is designed to support GDPR Article 7 (conditions for consent):

- **Specific** — purpose must be declared and auditable
- **Informed** — `authorization_ref` links to the consent document
- **Revocable** — OR-Set semantics, immediate effect
- **Audited** — every grant and revocation is in the immutable episodic ledger

Aevum does not generate GDPR compliance reports. The episodic ledger is
evidence that can be used in a compliance audit, not a report generator.
