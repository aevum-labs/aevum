# Aevum Threat Model

This document describes Aevum's trust assumptions, system boundaries,
what it protects against, and its known limitations. Read this before
deploying Aevum in a regulated or high-stakes environment.

Read this document alongside CONTROL_MAPPING.md.

---

## Version

Applies to: aevum-core v0.3.0+
Last reviewed: May 2026

---

## What Aevum is and is not

Aevum is a Python library that provides:

- A cryptographic audit trail (Ed25519-signed, SHA3-256 hash-chained)
- A consent-checked data access layer
- An append-only episodic ledger
- Human-in-the-loop review gates
- Five unconditional barriers (crisis, classification, consent,
  immutability, provenance)

Aevum is **not**:

- A network security tool (no mTLS, no SPIFFE/SVID identity)
- An authentication system (no identity issuance or token validation)
- A post-quantum cryptography implementation (Ed25519 is not
  quantum-resistant)
- A formal access-control enforcement boundary at the OS level (it is
  a library inside your process)
- A medical device or safety-critical system
- A system that prevents a determined insider with direct database access

---

## System Boundaries

### Inside Aevum's trust boundary

- The five governed functions (`ingest`, `query`, `review`, `commit`,
  `replay`) and their implementations in `aevum.core.engine`
- The five unconditional barriers
- The episodic ledger and sigchain (`urn:aevum:provenance`)
- The consent ledger (`urn:aevum:consent`)
- The knowledge graph (`urn:aevum:knowledge`)

### Outside Aevum's trust boundary

- The application process that imports and calls Aevum
- The Ed25519 private key (held in your process's memory by default)
- The storage backend (SQLite, Oxigraph, or PostgreSQL)
- The operating system and file system
- Network transport to the storage backend
- Any MCP host, HTTP client, or other caller of `aevum-server` or
  `aevum-mcp`
- The LLM or AI model making decisions

---

## Trust Assumptions

Aevum's guarantees depend on the following assumptions. If any
assumption is violated, the guarantee it supports degrades or fails.

### Assumption 1: The signing key is not compromised

**Guarantee supported:** Sigchain entries are authentic and have not
been fabricated after the fact.

**If violated:** An attacker with the private key can sign fabricated
AuditEvents that will verify as legitimate. The hash chain will appear
intact. There is no mechanism to detect this retroactively unless the
key compromise is identified through other means.

**Mitigation:** Use a KMS or HSM to hold the signing key outside the
application process. Implement key rotation on a defined schedule.
Monitor signing-key access.

---

### Assumption 2: The storage backend is not directly modified

**Guarantee supported:** Any modification to a stored AuditEvent breaks
the hash chain and is detectable on verification.

**If violated:** A database administrator with direct backend access can
delete or modify AuditEvents. The chain will break at the point of
modification and is detectable by `engine.verify_sigchain()` — but only
if verification is performed after the modification. Modification
followed by chain reconstruction using a compromised signing key would
not be detectable.

**Important distinction:** Aevum's ledger is tamper-**evident**, not
tamper-**proof**. It detects modification; it does not prevent it at
the storage layer.

**Mitigation:** Restrict database-level write access to the ledger
tables. Use PostgreSQL row-level security. For regulated deployments
where you need to prove the chain was intact at a specific moment,
consider external anchoring (RFC 3161 timestamps, OpenTimestamps).

---

### Assumption 3: The process running Aevum is not compromised

**Guarantee supported:** The five unconditional barriers cannot be
bypassed by configuration or complication code.

**If violated:** An attacker with code execution inside the Aevum
process can call the storage layer directly, bypassing the kernel. The
barriers are enforced in the kernel's code path — they are not OS-level
sandboxing.

**Mitigation:** Treat process-level compromise as a separate threat.
Apply standard application hardening: minimal privileges, container
isolation, seccomp profiles.

---

### Assumption 4: In-memory mode is not used in production

**Guarantee supported:** Sigchain integrity persists across restarts.

**If violated:** All data, the sigchain, and the consent ledger are
lost on process restart. No tamper-evidence survives.

**Mitigation:** In-memory mode is appropriate only for development and
testing. Use `aevum-store-oxigraph` or `aevum-store-postgres` for any
persistent workload.

---

## What Aevum Protects Against

| Threat | Coverage | Notes |
|---|---|---|
| Unauthorized data access (consent bypass) | Unconditional — Barrier 3 | Checked before every graph operation |
| Data ingestion without provenance | Unconditional — Barrier 5 | source_id required on every ingest |
| Above-clearance data access | Unconditional — Barrier 2 | Classification ceiling enforced at query |
| Crisis content propagation | Unconditional — Barrier 1 | See crisis detection limitations below |
| Ledger modification without detection | Detectable via verify_sigchain() | Tamper-evident, not tamper-proof |
| Complication code bypassing barriers | Architectural | Complications cannot access storage directly |
| Irreversible actions without approval | Via review() + veto-as-default | Requires application to call create_review() |
| Consent revocation delays | Immediate at next operation | Single-node only — see distributed limitation below |

---

## What Aevum Does Not Protect Against

| Threat | Status | Recommended mitigation |
|---|---|---|
| Network-level attacks (MitM, replay at transport layer) | Out of scope | TLS at reverse proxy; mTLS for internal services |
| Identity spoofing (fake actor claims) | Out of scope | JWT validation + actor mapping in your application |
| LLM prompt injection | Not directly | Input validation; purpose-built guardrail tooling |
| Training data poisoning | Out of scope | Separate data governance pipeline |
| Insider threat with direct DB admin access | Detected, not prevented | External anchoring; restricted DB access; RLS |
| Model bias or discriminatory outputs | Out of scope | Bias testing; NIST AI RMF MAP function |
| Quantum adversary forging signatures | Not protected | Ed25519 is not post-quantum; PQ migration planned |
| Cross-tenant isolation at OS level | Out of scope | Separate Engine instances per tenant; OS-level isolation |
| Data loss in in-memory mode | By design | Use persistent storage backend in production |

---

## Crisis Detection Limitations

Barrier 1 (Crisis) flags content matching crisis patterns before any
graph operation.

**What it does:** Checks ingested and queried content against defined
crisis indicators. Matching content stops the operation and returns a
crisis envelope.

**What it does not do:**

- It is not validated to any clinical standard
- It is not a medical device under FDA or EU MDR classification
- It does not replace human clinical judgment
- False negatives (missed crisis content) are possible
- False positives (incorrectly flagged content) are possible
- False-negative and false-positive rates are not currently published
  against a public benchmark

**If your application serves users in mental-health, crisis, or
vulnerable-population contexts:** do not rely on Barrier 1 alone.
Complement it with human review, clinical safety measures, and
domain-validated tooling. Barrier 1 is a first-line content screen,
not a clinical safety system.

---

## Consent Revocation Semantic

Aevum's consent ledger uses an OR-Set CRDT (Conflict-free Replicated
Data Type) for grant management.

**Single-node deployments:** Revocation is reliable and immediate.
`engine.revoke_consent_grant(grant_id)` makes data unreachable at the
next operation.

**Distributed deployments (multiple Engine instances):** The OR-Set's
"add wins on concurrent add/remove" merge semantic means that if a
grant-add and a grant-revoke for the same grant occur simultaneously
on two nodes, the add will win on merge. This is not the expected
behavior for permission revocation in regulated contexts, where revoke
should win.

**Mitigation for distributed deployments:** Coordinate consent
operations through a single authoritative node, or implement
application-level sequencing that ensures revocations are fully
propagated before new operations are permitted. A revoke-wins merge
strategy is on the roadmap.

---

## Replay Scope

`engine.replay(audit_id=...)` retrieves and cryptographically verifies
the signed record of a past operation from `urn:aevum:provenance`.

**What it does:** Returns the exact AuditEvent recorded at the time of
the original operation, with chain verification proving the record has
not been modified since it was written.

**What it does not do:**

- Does not re-execute the agent's reasoning
- Does not re-call the LLM
- Does not reconstruct the full knowledge graph state at the time of
  the original operation (the graph may have changed since)
- Does not guarantee byte-identical reproduction of LLM outputs

For auditing and forensics, replay provides a verified record of what
was ingested, queried, or committed. It does not provide a simulation
of what the agent would have done if run again today.

---

## Deployment Recommendations for Regulated Workloads

### HIPAA (healthcare, PHI)

- Use `aevum-store-postgres` with encrypted tablespace
- Hold the signing key in a KMS or HSM; do not leave it in process memory
- Restrict PostgreSQL write access to the ledger tables via row-level
  security
- Implement separate BAAs for any MCP/tool calls that process PHI
- Complement Aevum's audit controls with FIPS 140-3 validated encryption
  at rest; Aevum's default in-process Ed25519 configuration is not
  FIPS 140-3 validated

### EU AI Act high-risk systems

- Aevum addresses Article 12 (record-keeping) and parts of Article 19
- Separately implement Articles 9 (risk management), 10 (data governance),
  11 (technical documentation), 14 (human oversight), 15 (robustness)
- Retain logs for at least 6 months (Article 26(6)); 10 years for
  technical documentation (Article 18)
- See CONTROL_MAPPING.md for the full Article-by-Article mapping

### SOC 2 Type II

- Aevum's sigchain supports CC7.2 (monitoring) and CC7.3 (incident
  detection)
- Complement with network monitoring and access logging at the
  infrastructure layer

### Production minimum (all deployments)

- Use a persistent storage backend (not in-memory)
- Hold the signing key outside the application process where possible
- Run `engine.verify_sigchain()` on a scheduled basis, not only on-demand
- Alert on sigchain verification failures
- Restrict direct database write access to the ledger tables
