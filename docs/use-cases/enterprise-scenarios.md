# Enterprise Scenarios

Aevum's governed context kernel applies across regulated industries.
These scenarios illustrate the pattern: agent access, human review gates,
and a cryptographic audit trail.

## Financial services — Loan underwriting

**Problem:** A loan underwriting agent needs to access applicant financial data,
but every credit decision must be explainable and audited.

**Pattern:**

```python
engine.add_consent_grant(ConsentGrant(
    grant_id=f"applicant-{applicant_id}-underwriting",
    subject_id=f"applicant-{applicant_id}",
    grantee_id="underwriting-agent",
    operations=["ingest", "query"],
    purpose="loan-underwriting",
    classification_max=2,
    granted_at=...,
    expires_at=...,
    authorization_ref=f"loan-app-consent-{applicant_id}",
))
```

At decision time, the underwriting agent calls `engine.review()` with the
proposed decision. An underwriter approves or vetoes. The entire decision
chain — data ingested, context queried, decision requested, approval given —
is captured in the episodic ledger and replayable at any time.

**Regulatory value:** Every loan decision can be replayed to show exactly what
data the agent saw and what a human approved. FCRA and ECOA audit requirements
are satisfied by the episodic ledger.

---

## Healthcare — Care coordination

**Problem:** A care coordination agent needs to access patient data across
multiple care teams, but HIPAA requires strict access controls and audit trails.

**Pattern:**

```python
engine.add_consent_grant(ConsentGrant(
    grant_id=f"patient-{patient_id}-care-coord",
    subject_id=f"patient-{patient_id}",
    grantee_id="care-coordination-agent",
    operations=["ingest", "query"],
    purpose="care-coordination",
    classification_max=2,
    granted_at=...,
    expires_at=...,
    authorization_ref=f"hipaa-tpo-consent-{patient_id}",
))
```

The classification ceiling ensures the agent cannot access sensitive PHI
(classification 3 — mental health, substance abuse, HIV status) unless a
separate grant with `classification_max=3` is issued.

**Regulatory value:** Every patient data access is logged with the purpose,
the actor, and the consent grant reference. PHI access is auditable without
building custom audit infrastructure.

---

## Legal — Document review

**Problem:** An AI document review agent needs to access privileged legal
documents, but attorney-client privilege requires strict access controls and
a complete chain of custody.

**Pattern:**

```python
engine.ingest(
    data={"document_id": "DOC-001", "type": "contract", "content": "..."},
    provenance={
        "source_id": "document-management-system",
        "chain_of_custody": ["document-management-system", "legal-review-pipeline"],
        "classification": 3,
    },
    purpose="contract-review",
    subject_id=f"matter-{matter_id}",
    actor="document-review-agent",
)
```

The `chain_of_custody` field tracks every system that handled the document
before it reached Aevum. The classification 3 ceiling ensures only attorneys
with the appropriate consent grant can query this data.

**Regulatory value:** The sigchain provides a tamper-evident record of who
accessed which documents and when — supporting privilege logs and e-discovery.

---

## Insurance — Claims processing

**Problem:** A claims processing agent needs to correlate data from multiple
sources (medical records, police reports, photos), but each data source has
different consent and classification requirements.

**Pattern:**

Multiple consent grants, one per data source and purpose:

```python
# Medical records — highest classification
engine.add_consent_grant(ConsentGrant(
    ..., purpose="claims-processing", classification_max=3, ...
))

# Photos — lower classification
engine.add_consent_grant(ConsentGrant(
    ..., purpose="claims-processing", classification_max=1, ...
))
```

The query function's `classification_max` parameter acts as an additional
ceiling at query time, independent of the grant ceiling.

---

## The common pattern

All enterprise scenarios share the same structure:

1. **Consent first** — grants are established before any data is accessed
2. **Ingest with provenance** — every data source is identified and logged
3. **Query with purpose** — access is always scoped to a declared purpose
4. **Review for high-stakes decisions** — human gates before irreversible actions
5. **Commit outcomes** — business events are recorded in the episodic ledger
6. **Replay for audit** — any past decision can be reconstructed exactly

The episodic ledger and sigchain provide the cryptographic evidence needed
for regulatory audits without requiring custom audit infrastructure.

---

## What Aevum is not (for enterprise)

Aevum is not a compliance report generator. It produces evidence; your
compliance team interprets that evidence in context of the applicable regulation.

Aevum is not an identity provider. It consumes identity (via `actor` and
`grantee_id` fields); it does not issue tokens or manage authentication.

Aevum is not a data warehouse or data lake. It governs access to context;
your existing data infrastructure remains in place.

See [NON-GOALS](https://github.com/aevum-labs/aevum/blob/main/NON-GOALS.md) for
the full normative list.
