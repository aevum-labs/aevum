---
description: "Threat model for aevum-core: seven threats, mitigations for signing key compromise, audit trail tampering, and consent ledger manipulation."
---

# Threat Model

This document describes what Aevum protects against, what it does not
protect against, and the residual risks in a production deployment.

## Scope

This threat model covers `aevum-core` and `aevum-server` in a production
deployment with PostgreSQL backend, Cedar policy, and optional OPA sidecar.

## Assets

| Asset | Sensitivity | Protected by |
|---|---|---|
| Knowledge graph | High — contains personal data | Consent gates, classification ceiling |
| Episodic ledger | Critical — tamper-evident audit | Sigchain, append-only storage |
| Consent ledger | Critical — governs all access | Append-only, OR-Set semantics |
| Ed25519 signing key | Critical — enables chain forgery | KMS, process isolation |
| Application secrets (DB credentials, etc.) | High | Your secrets management |

## Threats and mitigations

### T1: Unauthorized data access by agent

**Threat:** An agent attempts to read or write data without a consent grant.

**Mitigation:** Barrier 3 (Consent) blocks the operation before any data
is accessed. Returns `error_code="consent_required"`.

**Residual risk:** If the consent ledger itself is compromised (T5), grants
could be fabricated.

---

### T2: Classification bypass

**Threat:** An agent with a low-classification grant attempts to access
high-classification data.

**Mitigation:** Barrier 2 (Classification Ceiling) redacts results above
the `classification_max` in the query. This fires in the kernel, not in policy.

**Residual risk:** A misconfigured consent grant with a high `classification_max`
grants access above the intended level. Principle of least privilege: set
`classification_max` to the minimum needed.

---

### T3: Audit trail tampering

**Threat:** An attacker modifies the episodic ledger to hide an operation
or alter a past decision.

**Mitigation:** The Ed25519 + SHA3-256 sigchain makes any modification
detectable. `engine.verify_sigchain()` returns `False` if the chain is broken.

**Residual risk:** The chain detects tampering but does not prevent it at
the storage layer. Physical access to the database enables modification.
Mitigate with: database access controls, write-once storage (S3 Object Lock),
and regular `verify_sigchain()` runs.

---

### T4: Signing key compromise

**Threat:** An attacker obtains the Ed25519 private key and forges valid
audit events or rebuilds a tampered chain.

**Mitigation:** Use a KMS for key storage. Rotate keys on a schedule.
Each event records `signer_key_id` — a key rotation creates a detectable break.

**Residual risk:** If the key is compromised before detection, the attacker
can forge events that pass `verify_sigchain()`. Mitigate with: KMS HSM
storage, key rotation monitoring, and out-of-band chain snapshots.

---

### T5: Consent ledger manipulation

**Threat:** An attacker adds fraudulent consent grants or removes revocations.

**Mitigation:** The consent ledger is append-only. Revocations are permanent
entries — they cannot be deleted. Adding a fraudulent grant requires write
access to the consent ledger, which requires database access.

**Residual risk:** Database write access enables fraudulent grants.
Mitigate with: strict PostgreSQL row-level security, audit of all database
writes, and separate DB credentials for read-only components.

---

### T6: Denial of service via OPA unavailability

**Threat:** An attacker takes down the OPA sidecar to block all operations.

**Mitigation:** Aevum fails closed — unavailable OPA means denied operations.
This prevents bypass but can be used as a DoS vector.

**Mitigation:** Put OPA behind a load balancer with health checks. Use
Cedar for all consent policy so OPA is only needed for infrastructure policy.
Consider `AEVUM_OPA_URL` unset for deployments where Cedar suffices.

---

### T7: Crisis keyword evasion

**Threat:** A user encodes crisis content in a way that evades Barrier 1
(e.g., leetspeak, unicode substitution).

**Mitigation:** Barrier 1 checks a defined keyword list. It is not a
general-purpose content moderation system.

**Residual risk:** Motivated evasion is possible. Aevum's crisis barrier
is a safety net, not a complete solution. If your application serves
vulnerable users, complement it with purpose-built content moderation.

---

## What Aevum does NOT protect against

- **Compromised application code** — if your application is compromised,
  an attacker can call any Aevum function with arbitrary parameters
- **Insider threats with database access** — a DBA can modify the storage layer
- **Key theft from process memory** — without KMS, the signing key is in RAM
- **Malicious content in payloads** — Aevum stores what you ingest; scan for
  malware before ingesting documents
- **Supply chain attacks on Aevum dependencies** — mitigate with `uv audit`

## Deployment security checklist

- [ ] Ed25519 key stored in KMS, not generated at startup
- [ ] PostgreSQL credentials use least-privilege role (no superuser)
- [ ] `aevum-server` behind TLS-terminating reverse proxy
- [ ] OPA behind health check and load balancer (or Cedar-only)
- [ ] `verify_sigchain()` run on a scheduled basis (cron or CI)
- [ ] Database write access restricted to application service account only
- [ ] `AEVUM_OPA_URL` unset if OPA is not needed
- [ ] `"aevum-core[cedar]"` installed (not permissive fallback)
- [ ] Dependency audit: `uv audit` in CI pipeline
