# HIPAA Security Rule — Technical Safeguards

**Status:** Guidance document  
**Applies to:** Deployments that process Protected Health Information (PHI)  
**Reference:** 45 CFR Part 164, Subpart C; 90 FR 800 (2025 NPRM)

---

## Overview

Aevum is not itself a covered entity or business associate. When deployers use Aevum to
process, store, or transmit PHI, Aevum contributes technical safeguards toward HIPAA
Security Rule compliance. This document maps Aevum's technical capabilities to the
relevant Security Rule provisions.

The 2025 NPRM (90 FR 800) proposes that safeguards currently designated "Addressable"
become Required. This document treats all safeguards as Required to anticipate that
standard.

---

## §164.312(b) — Audit Controls

**Requirement:** Implement hardware, software, and/or procedural mechanisms that record
and examine activity in information systems containing or using ePHI.

**What Aevum provides:**

Every governed operation (ingest, query, review, commit, replay) produces a signed entry
in the episodic ledger via `Sigchain.new_event()`. Each entry records:

| Field | Content |
|---|---|
| `event_id` | UUID7 time-ordered identifier |
| `event_type` | Operation type (e.g., `relate_graph_write`, `navigate`) |
| `actor` | Identity performing the operation |
| `system_time` | HLC timestamp (monotonic, causally consistent) |
| `valid_from` / `valid_to` | Valid-time interval for the operation |
| `payload_hash` | SHA3-256 hash of the operation payload |
| `prior_hash` | SHA3-256 hash of the previous chain entry (Merkle linkage) |
| `signature` | Ed25519 signature over all signing fields |

The episodic ledger is append-only. Barrier 4 (Audit Immutability) unconditionally
prevents deletion or modification of any chain entry — `ImmutableLedgerError` is raised
on any such attempt. Deployers can query the ledger by time window, actor, or event type
to satisfy audit review requirements under §164.308(a)(1)(ii)(D).

---

## §164.312(c)(2) — Integrity (Mechanism to Authenticate ePHI)

**Requirement:** Implement electronic mechanisms to corroborate that ePHI has not been
altered or destroyed in an unauthorized manner.

**What Aevum provides:**

Three independent integrity mechanisms:

1. **Per-entry Ed25519 signature:** Each chain entry is signed over SHA3-256(canonical
   JSON) of its signing fields. Any unauthorized modification invalidates the signature.

2. **SHA3-256 Merkle chain:** The `prior_hash` field of each entry contains the SHA3-256
   hash of the previous entry. Any modification to a historical entry invalidates all
   subsequent entries.

3. **`verify_chain(events)`:** `Sigchain.verify_chain()` traverses the complete chain
   from genesis — checking SHA3-256 Merkle linkage and Ed25519 signatures on every
   entry. Returns `True` only if the chain is entirely intact.

4. **Optional Rekor external anchoring** (`aevum-publish`): The `PublishComplication`
   submits chain checkpoints to Sigstore Rekor, a transparency log. This creates a
   third-party witness that the chain existed at a specific time, preventing an operator
   from silently replacing the chain after the fact.

---

## §164.312(a)(2)(iv) — Encryption and Decryption

**Requirement:** Implement a mechanism to encrypt and decrypt ePHI.

**What Aevum provides:**

Aevum enforces through Cedar policy (`gdpr_pii.cedar`) that raw PHI is never stored in
the sigchain payload. The sigchain stores only:

- A pseudonymous subject identifier (`subject_id`)
- A SHA-256 hash of the PHI at ingestion time (`data_hash`)
- A key ID reference — not the key material (`key_id`)

**What the deployer must provide:**

- **At-rest encryption** for the off-chain PHI store and the consent ledger database.
  Aevum does not encrypt its own storage.
- **In-transit encryption** (TLS) for all API endpoints.
- **Per-subject encryption keys** following the pattern in
  `docs/compliance/gdpr-article-17.md`. This same crypto-shredding pattern applies to
  PHI disposal requirements.
- **Key management infrastructure** (e.g., HashiCorp Vault, AWS KMS, GCP Cloud KMS).

---

## PHI Handling Pattern

PHI handling in an Aevum deployment follows the GDPR Article 17 pattern. The pattern is
identical for PHI and PII:

1. Store PHI off-chain in a separately encrypted, erasable datastore — never in the
   sigchain payload.
2. Store in the sigchain only: `subject_id` (pseudonymous), `data_hash` (SHA-256 of
   PHI), `key_id` (reference to the encryption key).
3. For PHI disposal: perform crypto-shredding (delete the per-subject KEK from the
   secrets manager), then delete the PHI from the off-chain store.

The `gdpr_pii.cedar` policy enforces Step 1 unconditionally. Steps 2 and 3 are deployer
responsibilities.

For the complete normative description of this pattern — including code samples and the
DEK vault implementation — see `docs/compliance/gdpr-article-17.md`.

---

## Deployer Checklist

The following controls are required for HIPAA compliance and are **not** provided by
Aevum:

| Control | Deployer responsibility |
|---|---|
| BAA with Aevum Labs | Execute a Business Associate Agreement if Aevum Labs processes PHI on your behalf |
| Workforce training | HIPAA-required training for all staff accessing systems that use Aevum |
| Access management | User provisioning, credential rotation, and MFA for actors interacting with Aevum |
| Physical safeguards | §164.310 — data centre physical controls for servers running Aevum |
| Network encryption (TLS) | Encrypt all traffic to and from Aevum endpoints |
| At-rest encryption | Encrypt the Aevum storage, consent ledger database, and off-chain PHI store |
| Key management | Per-subject KEK generation, storage, rotation, and destruction |
| Off-chain PHI store | Build and maintain the erasable off-chain store for PHI content |
| Incident response | Breach detection, 60-day HIPAA notification, and response procedures |
| Risk analysis | §164.308(a)(1)(ii)(A) — documented risk analysis for the full system |
| Contingency plan | §164.308(a)(7) — backup and recovery for the episodic ledger and PHI stores |

---

## References

- 45 CFR Part 164, Subpart C — HIPAA Security Rule
- 90 FR 800 — HHS 2025 NPRM: HIPAA Security Rule Cybersecurity Update
- `docs/compliance/gdpr-article-17.md` — Off-chain PHI pattern (crypto-shredding)
- `packages/aevum-core/src/aevum/core/barriers.py` — Barrier 4 (Audit Immutability)
- `packages/aevum-core/src/aevum/core/audit/sigchain.py` — `verify_chain()`
- `packages/aevum-core/src/aevum/core/policies/gdpr_pii.cedar` — PHI in-payload barrier
