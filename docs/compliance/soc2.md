# SOC 2 Type II — Evidence Guide

**Status:** Guidance document  
**Audience:** Organizations undergoing SOC 2 Type II audits that use Aevum  
**Note:** Aevum is not the audit subject — your organization is. This guide explains
what evidence Aevum produces toward AICPA Trust Services Criteria (TSC).

---

## Overview

SOC 2 Type II audits evaluate whether an organization's controls operated effectively
over a defined period (typically 6–12 months). Aevum's episodic ledger, consent ledger,
and policy engine produce auditable evidence that maps to several Trust Services
Criteria. This guide explains what Aevum produces, what it does not produce, and how to
extract evidence for your auditor.

---

## Trust Services Criteria Mapping

| TSC | Criterion | What Aevum provides |
|---|---|---|
| CC6.1 | Logical access controls | Cedar policy decisions with sigchain evidence; consent grants as authorization records |
| CC6.2 | Authentication | Consent grant verification (subject_id + grantee_id + purpose); SPIFFE workload identity via `aevum-spiffe` (optional) |
| CC7.2 | Monitoring | Sigchain as immutable activity log with actor, timestamp, event type; Rekor external anchoring for third-party witnessing |
| CC8.1 | Change management | Rekor-anchored release signing; complication lifecycle state machine (registered → approved → active → suspended) |

---

### CC6.1 — Logical Access Controls

Every `query` and `replay` operation requires a valid `ConsentGrant` before any data is
accessed. Consent grants are the access authorization record. Each grant records:

- **Who** can access: `grantee_id`
- **Whose data** is covered: `subject_id`
- **What operations** are authorized: `operations` — subset of {ingest, query, replay, export}
- **For what purpose**: `purpose` — specific, non-vague statement enforced by validator
- **Until when**: `expires_at` — grants expire and must be renewed
- **At what classification level**: `classification_max` (0–3)

Cedar policy decisions are evaluated before every operation and can be logged at the
integration boundary. An auditor can export the consent ledger to show the complete
authorization history for a subject or grantee over the audit period.

Barrier 2 (Classification Ceiling) unconditionally redacts results above the actor's
clearance level, independent of consent grants. This provides defense-in-depth on top
of consent-based access control.

### CC6.2 — Authentication

Aevum's consent model requires `subject_id` and `grantee_id` for every data access
operation. The `grantee_id` is the accessing actor's identity; the deployer is
responsible for authenticating this identity at their integration boundary.

For service-to-service authentication, `aevum-spiffe` (optional complication) integrates
SPIFFE/SPIRE workload identity. When active, the SPIFFE SVID (X.509 or JWT) is used as
the `grantee_id`, providing cryptographically verified service identity that auditors can
trace back to a specific workload.

### CC7.2 — Monitoring

The sigchain provides continuous monitoring evidence — an immutable, sequential log of
every governed operation. Each entry records:

- `event_type`: what operation occurred
- `actor`: which identity performed it
- `system_time`: HLC timestamp (monotonic, causally consistent)
- `payload_hash`: SHA3-256 fingerprint of the operation payload
- `signature`: Ed25519 signature — tamper detection for that entry

`verify_chain()` produces a binary integrity result: is the complete chain intact from
genesis? A `True` result means no entry has been modified, deleted, or reordered since
the chain was established. This is the programmatic evidence for your auditor.

For external witnessing, `aevum-publish` submits chain checkpoints to Sigstore Rekor
(public or private transparency log). This creates a third-party audit witness that
cannot be retroactively altered even by the operator — the checkpoint is in Rekor's
append-only log.

### CC8.1 — Change Management

**Release signing:** Every Aevum release is built via GitHub Actions with OIDC Trusted
Publishing (no static API keys) and build provenance attestations. The CycloneDX SBOM
for each release is published as a release artifact, providing a verifiable bill of
materials for change review.

**Complication lifecycle:** Extensions to Aevum follow a governed lifecycle:

| State | What it means | Audit record |
|---|---|---|
| Registered | Known to the engine, not active | None required |
| Approved | Explicitly approved by an operator | Sigchain entry |
| Active | Running | — |
| Suspended | Deactivated by operator | Sigchain entry |

No complication can become active without an explicit operator approval that is recorded
in the episodic ledger. Auditors can produce a complete history of which extensions were
active during the audit period.

---

## What an Auditor Can Extract from Aevum

### Export sigchain entries for a time window

```python
from aevum.core import Engine

engine = Engine()
events = engine.ledger.events_in_window(
    from_ts="2025-01-01T00:00:00Z",
    to_ts="2025-12-31T23:59:59Z",
)
for event in events:
    print(event.event_id, event.actor, event.event_type, event.system_time)
```

### Verify chain integrity

```python
from aevum.core.audit.sigchain import Sigchain

chain = Sigchain()  # initialized with the same signing key as the running engine
events = engine.ledger.all_events()
integrity_ok = chain.verify_chain(events)
print("Chain intact:", integrity_ok)
# True = no modifications since genesis
```

### Produce a Rekor inclusion proof

If `aevum-publish` is active and configured with a Rekor instance:

```python
import httpx

rekor_url = "https://rekor.sigstore.dev"
uuid = "<rekor_entry_uuid>"  # logged by PublishComplication on each checkpoint
response = httpx.get(f"{rekor_url}/api/v1/log/entries/{uuid}")
entry = response.json()
# entry contains: body (signed payload), integratedTime, logID, logIndex
# This is third-party witnessing proof — the checkpoint was in Rekor's log at integratedTime.
```

### Export consent grant history

```python
from aevum.core.consent.ledger import ConsentLedger

ledger = ConsentLedger(db_path="consent.db")
grants = ledger.all_grants()
for grant in grants:
    print(
        grant.grant_id,
        grant.subject,
        grant.purpose,
        grant.granted_at,
        grant.expires_at,
    )
```

---

## What Aevum Does Not Provide

| Gap | Deployer responsibility |
|---|---|
| SOC 2 Type II report | You engage the auditor and produce the report |
| Penetration testing | Aevum does not test your deployment's network security |
| Vendor management (CC9.2) | You manage Aevum Labs as a vendor; obtain SOC 2 report or equivalent |
| Business continuity | Backup and recovery of the episodic ledger and consent database |
| Logical access provisioning | User and service account management at your identity provider |
| Evidence aggregation | Collecting Aevum audit data alongside other system logs for the full audit trail |
| Retention policy enforcement | Aevum does not delete or archive events on a schedule |

---

## References

- AICPA Trust Services Criteria (2017, revised 2022)
- `packages/aevum-core/src/aevum/core/audit/sigchain.py` — `verify_chain()`
- `packages/aevum-core/src/aevum/core/consent/models.py` — `ConsentGrant`
- `packages/aevum-core/src/aevum/core/consent/ledger.py` — `all_grants()`
- `packages/aevum-core/src/aevum/core/barriers.py` — Unconditional barriers
- `docs/compliance/gdpr-article-17.md` — Crypto-shredding and erasure pattern
