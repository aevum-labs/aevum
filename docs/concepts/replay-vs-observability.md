---
description: "Observability tools record what an AI agent did. Deterministic replay lets you reproduce it exactly. This page explains what that distinction requires architecturally."
---

# Logs vs. Replay: What Reproducing an Agent Run Actually Requires

Every major AI observability platform records what your agent did. None of them reproduce exactly what it did — same LLM responses, same tool outputs, same state at decision time. This page explains why that gap exists, what closing it actually requires, and how Aevum's `replay` function differs from checkpoint-based and trace-based approaches.

## What observability tools give you

| Tool | What it records | What "replay" means for it | What it cannot reproduce |
|------|-----------------|---------------------------|--------------------------|
| LangSmith / LangFuse | OpenTelemetry spans, observations, scores | Re-run a trace against a new model version | Original LLM sampling, tool-version state |
| LangGraph Time Travel | Graph state checkpoints at each node | Fork execution from a saved checkpoint | Non-deterministic LLM sampling between checkpoints |
| Docker Cagent | YAML cassettes of HTTP tool calls | Play back cassettes in testing | Production audit evidence, tamper-evident storage |
| Arize / Phoenix | OpenInference traces, evals | Not offered — observability only | N/A by design |
| Aevum | Sigchain-anchored episodic ledger | Exact payload reconstruction from any past `audit_id` | Real-time LLM token streaming (records result, not stream) |

> **Note:** LangSmith's "replay" re-runs a trace against a new model version; it does not reconstruct the original execution. These are different operations with different guarantees.

## What deterministic replay actually requires

**Recorded outputs, not re-executed inputs.** Replay must return the stored result, not call the LLM again. If two calls to `engine.replay` with the same `audit_id` produce different data, the operation is re-execution, not replay. The Aevum specification is explicit on this point: "Two replay calls with the same audit_id and the same actor clearance MUST produce identical OutputEnvelopes." (Spec Section 8.7) This guarantee holds regardless of how much time has elapsed, what model version is currently deployed, or how the knowledge graph has changed since the original call.

**Immutable storage.** The recording must be provably unmodified. A mutable log can be edited after the fact — a row can be updated, a file can be overwritten, a database can be dropped and reconstructed. A hash-chained, signed ledger cannot be silently altered: each entry includes the SHA3-256 digest of the preceding entry, forming a chain where any alteration invalidates all subsequent hashes. An auditor calling `engine.verify_sigchain()` detects the alteration immediately. This property is what distinguishes an episodic ledger from a conventional application log.

**Scoped access control.** Not every identity should be able to replay every decision. A billing agent that made the original ingest call does not automatically gain access to replay it six months later in an audit context. An audit agent must hold an explicit consent grant with `"replay"` in its operations list and a purpose that matches the audit context. This separation ensures that operational access does not confer audit access, and that replay cannot be used as a covert read path by actors who lack query consent.

**Separation from the live knowledge graph.** The `query` function reads from `urn:aevum:knowledge` — the working graph that changes as new data arrives. The `replay` function reads from `urn:aevum:provenance` — the immutable provenance graph that records what was true at ingestion time and never changes. A `query` call today returns the current state of the graph; a `replay` call for an `audit_id` from six months ago returns exactly what was recorded then, unaffected by any subsequent ingestion, revocation, or reclassification.

## How Aevum replay works

The following example shows the complete flow from ingest through replay and sigchain verification using the billing domain.

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

# Grant the billing agent consent to ingest and query
engine.add_consent_grant(ConsentGrant(
    grant_id="billing-grant-001",
    subject_id="customer-42",
    grantee_id="billing-agent",
    operations=["ingest", "query"],
    purpose="billing-inquiry",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Grant the audit agent consent to replay
engine.add_consent_grant(ConsentGrant(
    grant_id="audit-grant-001",
    subject_id="customer-42",
    grantee_id="audit-agent",
    operations=["replay"],
    purpose="billing-audit",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Billing agent ingests a decision
ingest_result = engine.ingest(
    data={
        "invoice_id": "INV-2026-001",
        "amount": 1500.00,
        "status": "flagged-for-review",
        "reason": "amount exceeds threshold",
    },
    provenance={
        "source_id": "billing-system",
        "chain_of_custody": ["billing-system", "billing-agent"],
        "classification": 1,
        "model_id": "gpt-4o-2024-11-20",
    },
    purpose="billing-inquiry",
    subject_id="customer-42",
    actor="billing-agent",
    idempotency_key="INV-2026-001-flag",
)

print(ingest_result.status)    # ok
print(ingest_result.audit_id)  # urn:aevum:audit:0196...

# Six months later — audit agent replays the exact decision
replay_result = engine.replay(
    audit_id=ingest_result.audit_id,
    actor="audit-agent",
)

print(replay_result.status)                                # ok
print(replay_result.data["replayed_payload"]["amount"])    # 1500.0
print(replay_result.data["event_metadata"]["actor"])       # billing-agent

# Verify the entire sigchain is intact
print(engine.verify_sigchain())  # True
```

Each block demonstrates a distinct guarantee. The first `add_consent_grant` call establishes that `billing-agent` can ingest and query data for `customer-42` under the `billing-inquiry` purpose. The second establishes that `audit-agent` can replay under `billing-audit` — a separate purpose with no write access. The `ingest` call records both the data payload and its provenance chain. The `replay` call six months later returns the exact payload that was recorded, not the current state of the knowledge graph. The `audit-agent` cannot call `ingest` or `query` — its grant covers only `replay`; attempting either would produce `status="error"` with `error_code="consent_required"`.

## See also

- [The Sigchain](sigchain.md) — how the hash chain and Ed25519 signing work
- [Audit Events](../reference/audit-events.md) — the AuditEvent schema
- [Audit Trails and Article 12](audit-trails.md) — compliance implications
