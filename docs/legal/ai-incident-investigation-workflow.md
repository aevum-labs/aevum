# AI Incident Investigation Workflow

**Version:** 0.1 (Draft)
**Modeled on:** NTSB Aviation Investigation Manual
**Standards reference:** NIST CAISI AI Agent Standards Initiative (launched February 17, 2026)

*This document does not constitute legal advice. Obtain qualified legal and
compliance review before using this workflow in a formal regulatory proceeding.*

---

## Overview

This workflow provides the "AI equivalent of the NTSB accident investigation
procedure" — a structured, evidence-first process for investigating AI agent
incidents using Aevum's sigchain, receipt store, and replay capability.

Aevum receipts serve as the technical equivalent of an aircraft's Cockpit Voice
Recorder (CVR) and Flight Data Recorder (FDR): tamper-evident, cryptographically
signed, and independently verifiable without access to the original system.

---

## 1. Notification and Custody

### Who triggers an investigation

- **Deployer** detects a policy violation, safety barrier trip, or human override rejection
- **Regulator** initiates under EU AI Act Article 73 (serious incident reporting)
- **Third party** alleges harm attributable to the AI system

### Immediate actions

1. Run `aevum verify-receipt --hash <receipt_hash>` to confirm receipt integrity
   at the moment of incident detection. Record the output as timestamped evidence.

2. **Lock the session window.** Receipts in the relevant time window are
   automatically escalated to `crash_protected` tier on any DENY barrier trip
   (Session 2 escalation logic). Verify this escalation occurred.

3. **Do NOT modify the sigchain or receipt store** pending investigation.
   The append-only guarantee (Frozen Invariant 5) means modification is detectable,
   but any attempt degrades the evidentiary chain.

4. Document the incident detection timestamp, the session ID, and the receipt
   hash at the moment of detection.

---

## 2. Evidence Collection

### Tools

| Command | Purpose |
|---------|---------|
| `aevum verify-receipt <file>` | Verify receipt integrity offline (no server required) |
| `aevum verify-receipt --hash <hash>` | Look up receipt by hash |
| `aevum store migrate-receipts` | Confirm all receipts are in the SQLite store |
| `GET /sandbox/sigchain` | Retrieve full sigchain (demo endpoint; use kernel API in production) |

### Evidence bundle contents

Assemble the following for the factual record:

1. **All COSE_Sign1 receipts** for the session (time-bounded window around incident)
2. **SCITT inclusion proofs** (when a transparency log is configured)
3. **FRE 902(13) certification** — see `docs/legal/fre-902-13-certification-template.md`
4. **Exceedance event log** — from `ExceedanceDetector` if configured
5. **Model identity hash** (`model_identity_hash` field in `AevumReceipt`)
6. **Policy version** at time of incident (`policy_version` field)
7. **Tool allowlist hash** at time of incident
8. **Barrier evaluation results** (`barrier_evaluations` field per receipt)

---

## 3. Analysis Group

Modeled on the NTSB CVR Group structure:

| Participant | Role |
|-------------|------|
| AI system operator (deployer) | Provides operational context; custodian of the receipt store |
| Model provider representative | Required if model behavior (not tool use) is in question |
| Tool vendor | Required if a specific tool call is the subject of investigation |
| Regulator | Required for formal investigations under EU AI Act Art. 73 or equivalent |
| Independent forensic verifier | Uses `aevum verify-receipt` without server access — verifies receipt integrity independently |

The independent forensic verifier must be able to verify the evidence bundle
using only the Aevum public key and the COSE_Sign1 receipts. No access to
the production system should be required for verification.

---

## 4. Factual Report

Document the following from the evidence bundle:

### Sequence of events (sigchain entries, chronological)

Reconstruct the timeline from sigchain entries. Each entry contains:
- `timestamp` (HLC — hybrid logical clock)
- `actor` (agent identity)
- `event_type`
- `payload_hash`
- `prior_hash` (chain link)

### Barrier evaluation results

Each receipt includes `barrier_evaluations`. Record which barriers were
evaluated and their outcomes:

| Barrier | Name | Outcome |
|---------|------|---------|
| 1 | Crisis | PASS / DENY |
| 2 | Classification ceiling | PASS / DENY |
| 3 | Consent | PASS / DENY |
| 4 | Audit immutability | PASS / DENY |
| 5 | Provenance | PASS / DENY |

### Exceedance events

If `ExceedanceDetector` was configured, list all exceedance events in the
session window with their detected parameter, threshold, and actual value.

### DSSAD-equivalent events

Document:
- `handoff_type` — for any agent-to-agent handoff or ODD exit
- `human_override_action` — for any human intervention event
- `TRANSITION_DEMAND` events — where the system requested human review

### Model and policy identity at time of incident

- `model_identity_hash` — identifies the exact model version that acted
- `policy_version` — identifies the Cedar/OPA policy bundle that evaluated actions

---

## 5. Probable Cause

Use the following determination framework:

| Question | Evidence source |
|----------|-----------------|
| Was the action within the policy? | Cedar evaluation result in `barrier_evaluations` |
| Was a barrier tripped? | `barrier_evaluations` for Crisis/Consent/ClassificationCeiling/AuditImmutability/Provenance |
| Was there human oversight? | `human_override_action` field; `TRANSITION_DEMAND` events |
| Did the agent operate outside its ODD? | `handoff_type == ODD_EXIT` |
| Was the policy appropriate for the situation? | Compare `policy_version` against policy changelog |
| Was the model the expected model? | Compare `model_identity_hash` against deployment record |

---

## 6. Regulatory Notification

### EU AI Act Article 73 (serious incidents)

**Definition:** Serious incident = death, serious harm to health/safety, significant
property damage, or significant disruption to critical infrastructure.

**Notification deadline:** 3 days from incident detection (initial notification);
15 days for a full report.

**Notification package:**
- Incident description and timeline (from sigchain)
- Affected persons (if applicable)
- Immediate mitigation actions taken
- Aevum receipt bundle as the technical evidence package

### Other jurisdictions

| Jurisdiction | Standard | Notification trigger | Deadline |
|-------------|----------|---------------------|---------|
| US (NIST CAISI) | SP guidance expected 2027 | TBD | TBD |
| UK | ICO AI Auditing Framework | Significant harm | 72 hours (if personal data breach) |
| EU (DORA) | Art. 19/20 | ICT-related incident | 4 hr initial / 72 hr intermediate / 1 mo final |

---

## 7. Standards Reference

This workflow is proposed as a contribution to:

- **IEEE P2893** — Standard for the Governance of AI Agents (in development)
- **NIST CAISI AI Agent Standards Initiative** — launched February 17, 2026; RFI
  comment period closed March 2026; SP guidance expected 2027

The NTSB-modeled structure (notification → custody → evidence → analysis →
probable cause → regulatory notification) provides a domain-neutral template
that regulators can adopt for AI incident investigation procedures without
requiring AI-specific rulemaking from scratch.

---

## See also

- `docs/legal/fre-902-13-certification-template.md` — FRE 902(13) certification for US federal court
- `docs/learn/compliance-mapping.md` — full regulatory coverage table
- `docs/standards/iso42001-evidence-map.md` — ISO 42001 Annex A evidence pack
