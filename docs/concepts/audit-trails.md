---
description: "EU AI Act Article 12 requires automatic, tamper-evident recording for high-risk AI systems. This guide maps each sub-clause to a working Python implementation using Aevum."
---

# Audit Trails and EU AI Act Article 12: A Python Implementation Guide

EU AI Act Article 12 mandates automatic logging for high-risk AI systems. High-risk obligations become enforceable on 2 August 2026 under Article 85. This guide maps each Article 12 sub-clause to a concrete implementation using Aevum's episodic ledger and sigchain.

## What Article 12 requires

The regulation text:

> **Article 12(1):** High-risk AI systems shall technically allow for the automatic recording of events ('logs') throughout the lifetime of the system.

> **Article 12(2):** In order to ensure a level of traceability of the AI system's functioning that is appropriate to the intended purpose of the system, logging capabilities shall enable the recording of events relevant for:
>
> (a) identifying situations that may result in the AI system presenting a risk within the meaning of Article 79(1) or lead to a substantial modification;
>
> (b) facilitating the post-market monitoring referred to in Article 72; and
>
> (c) monitoring the operation of high-risk AI systems referred to in Article 26(5).

Source: [EU Artificial Intelligence Act, Article 12](https://artificialintelligenceact.eu/article/12/)

This guide covers the technical implementation of 12(1) and 12(2). For high-risk system scope, see Annex III.

## Engineering interpretation

| Clause | What it requires technically | Aevum primitive |
|--------|------------------------------|-----------------|
| Article 12(1) | Automatic recording — fires on every operation without manual intervention | Every engine call appends to the episodic ledger unconditionally |
| Article 12(2)(a) | Logs must enable identification of situations presenting risk or triggering a substantial modification | Every `AuditEvent` records `event_type`, `actor`, `timestamp`, and `status` — anomalous patterns are detectable via `get_ledger_entries()` |
| Article 12(2)(b) | Logs must facilitate post-market monitoring by market surveillance authorities | The sigchain provides a complete, tamper-evident, replayable record accessible to authorised auditors via `replay` |
| Article 12(2)(c) | Logs must support monitoring of deployer obligations under Article 26(5) | `get_ledger_entries()` gives deployers a full operational record; `verify_sigchain()` confirms integrity |
| Article 26(6) | Minimum 6-month log retention | Ledger is append-only; entries are never deleted |

## What Article 12 does not specify — and what that means

Article 12 does not mandate a specific log format, a cryptographic signature scheme, or tamper-evident storage. But implementing those properties is the rational engineering choice: tamper-evident storage (hash chaining plus signatures) satisfies Article 15 (accuracy and robustness) simultaneously, an immutable signed ledger is the control that satisfies ISO/IEC 42001 Clause 10 and SOC 2 Trust Services Criterion PI1.2, and a mutable log that satisfies Article 12's letter but can be edited after the fact provides no actual audit value in a contested proceeding. The community demand for this implementation guidance is a matter of public record — LangChain GitHub issue #35357 ("Feature: Structured compliance audit logging for EU AI Act Article 12") documents practitioner requests for exactly this pattern.

## Working implementation

The following example demonstrates automatic recording, provenance, retention query, sigchain verification, and replay for regulatory audit. The healthcare domain is used because it represents the clearest regulated-industry case: PHI under classification level 3, a FHIR R4 source system, and a clinical AI agent acting as grantee.

```python
"""
EU AI Act Article 12 — reference implementation using Aevum.

Demonstrates: automatic recording, provenance, retention query,
sigchain verification, and replay for regulatory audit.
"""

import datetime
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

# Consent must precede any data operation — Barrier 3
engine.add_consent_grant(ConsentGrant(
    grant_id="care-coordination-grant-001",
    subject_id="patient-8821",
    grantee_id="clinical-ai-agent",
    operations=["ingest", "query"],
    purpose="care-coordination",
    classification_max=3,              # sensitive — PHI
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
    authorization_ref="signed-consent-form-8821-2026-01-01",
))

# Article 12(2)(b) — reference database: the FHIR R4 endpoint
# Article 12(2)(c) — input data: the observation payload
result = engine.ingest(
    data={
        "resourceType": "Observation",
        "status": "final",
        "code": {"coding": [{"system": "http://loinc.org", "code": "8867-4"}]},
        "valueQuantity": {"value": 48, "unit": "beats/minute"},
        "effectiveDateTime": "2026-05-01T14:32:00Z",
    },
    provenance={
        "source_id": "fhir-r4-endpoint-prod",
        "chain_of_custody": ["ehr-system", "fhir-r4-endpoint-prod", "clinical-ai-agent"],
        "classification": 3,           # PHI — classification_max=3 required
        "model_id": "clinical-triage-v2.1",
    },
    purpose="care-coordination",
    subject_id="patient-8821",
    actor="clinical-ai-agent",
    idempotency_key="obs-8821-2026-05-01T14:32:00Z",  # prevents duplicate on retry
)

# Article 12(1) — automatic recording: audit_id is always returned
print(f"Recorded: {result.audit_id}")   # urn:aevum:audit:0196...
print(f"Status:   {result.status}")     # ok

# Article 12(2)(a) — period of each use: inspect the ledger entry
entries = engine.get_ledger_entries()
latest = entries[-1]
print(f"Timestamp: {latest['timestamp']}")    # UTC ISO 8601
print(f"Actor:     {latest['actor']}")        # clinical-ai-agent
print(f"Event:     {latest['event_type']}")   # ingest.accepted

# Article 26(6) — 6-month retention: filter ledger by date range
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=180)
retained = [
    e for e in engine.get_ledger_entries()
    if datetime.datetime.fromisoformat(e["timestamp"]) > cutoff
]
print(f"Entries within 6-month window: {len(retained)}")

# Replay — deterministic reconstruction for regulatory audit
# Same audit_id always returns same payload — Spec Section 8.7

# Grant audit agent replay access
engine.add_consent_grant(ConsentGrant(
    grant_id="audit-grant-001",
    subject_id="patient-8821",
    grantee_id="compliance-auditor",
    operations=["replay"],
    purpose="regulatory-audit",
    classification_max=3,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
))

replay_result = engine.replay(
    audit_id=result.audit_id,
    actor="compliance-auditor",
)
original_value = replay_result.data["replayed_payload"]["valueQuantity"]["value"]
print(f"Replayed heart rate: {original_value} bpm")   # 48

# Tamper-evidence verification — Barrier 4 (audit immutability)
chain_intact = engine.verify_sigchain()
print(f"Sigchain intact: {chain_intact}")  # True
```

Each section of the example maps to a specific regulatory requirement. The `add_consent_grant` call at the top satisfies Barrier 3 (consent as precondition for any write) and simultaneously creates a ledger entry that can be replayed later under `regulatory-audit` purpose. The `ingest` call's `provenance` argument provides Article 12(2)(b) compliance: `source_id` identifies the reference database (`fhir-r4-endpoint-prod`) and `chain_of_custody` records every system the data passed through before reaching the kernel. The `data` payload is stored verbatim, satisfying 12(2)(c). The `get_ledger_entries()` call with a date filter demonstrates 6-month retention query — the ledger never deletes entries, so the filter is a view over the complete record. The `replay` call at the end provides deterministic reconstruction: the same `audit_id` will return the same heart-rate reading regardless of what the production FHIR endpoint contains today.

## What Aevum does not cover

Aevum produces the evidence; the compliance team interprets it. Aevum is not a compliance report generator. For Annex III high-risk scope assessment, technical documentation under Article 11, and conformity assessment procedures, see the [EU AI Act Service Desk](https://ai-act-support.ec.europa.eu) and the forthcoming prEN ISO/IEC 24970 AI system logging standard.

## See also

- [The Sigchain](../learn/architecture.md#the-sigchain)
- [Replay vs. Observability](replay-vs-observability.md)
- [Audit Events reference](../reference/api.md#auditevent)
- [Deployment guide](../learn/deployment.md)
