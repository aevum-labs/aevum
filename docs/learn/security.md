---
description: "Aevum's security architecture, documented threat model,
and answers to common security questions — for engineers evaluating
production deployment."
---

# Security

## Authentication

Aevum does not implement authentication. Every operation takes an `actor`
parameter — a string identifier for the caller. Your application is responsible
for verifying that the caller is who they say they are before calling Aevum.

For production deployments with OIDC:

```python
# Validate JWT with aevum-oidc
from aevum.oidc import OIDCComplication

oidc = OIDCComplication(jwks_uri="https://your-idp/.well-known/jwks.json")
engine.install_complication(oidc, auto_approve=True)

# After validation, use the verified subject as actor
actor = verified_token["sub"]  # e.g., "user:alice@example.com"
```

The `actor` field is immutable in the audit event once written.

## Authorization

Authorization operates at three layers:

### Layer 1: Absolute barriers (unconditional)

The five absolute barriers in `barriers.py` fire before any policy evaluation.
They cannot be overridden by Cedar, OPA, or any configuration.

See [Architecture](/learn/architecture/#five-absolute-barriers).

### Layer 2: Cedar (in-process)

Cedar handles consent and purpose policy decisions in-process.
Install with: `pip install "aevum-core[cedar]"`

Without Cedar, the kernel warns and falls back to permissive decisions
(except for barrier fast-path denials, which still fire).

### Layer 3: OPA (optional HTTP sidecar)

For infrastructure policy (network access, resource limits, tenant isolation),
an OPA sidecar can be configured:

```bash
export AEVUM_OPA_URL=http://your-opa-host:8181
```

Aevum fails closed — if OPA is configured but unreachable, all operations
are denied.

## Cryptographic audit trail

Every operation is signed with Ed25519 and chained with SHA3-256:

- **Ed25519** — 128-bit security, fast signing, compact signatures
- **SHA3-256** — NIST-approved, resistance to length-extension attacks
- **UUID v7** — time-ordered event IDs, sortable without timestamp metadata
- **Hybrid Logical Clock** — monotonic timestamps, safe in distributed systems

The signing key is generated at startup. For production:
- Use your KMS to generate and store the key
- Rotate keys on a schedule; Aevum records `signer_key_id` in every event
- Back up the public key separately from the ledger

## Data at rest

Aevum does not encrypt data at rest directly. Encryption is handled by your
storage layer:

| Backend | Encryption approach |
|---|---|
| In-memory | N/A (process memory) |
| Oxigraph | File system encryption (OS-level or LUKS) |
| PostgreSQL | Transparent data encryption (pgcrypto, PGDATA encryption) |

## Data in transit

Aevum communicates over:
- In-process function calls (no network) when using aevum-core directly
- HTTP to OPA sidecar (use mTLS for production)
- HTTP to OIDC JWKS endpoint (TLS required)

`aevum-server` (FastAPI) serves over HTTP. Put it behind a TLS-terminating
reverse proxy (nginx, Traefik, or your cloud load balancer) for production.

## Secret management

Aevum itself has no secrets to manage except the Ed25519 signing key.
For production:
1. Generate the key in your KMS
2. Pass it to `Engine(sigchain=Sigchain(signer=InProcessSigner(private_key=your_key)))`
3. Store the public key for verification

Third-party dependencies (PostgreSQL credentials, OPA URL, OIDC JWKS URI)
should be managed with your standard secrets management tooling
(Vault, AWS Secrets Manager, Kubernetes Secrets, etc.).

## Dependency security

All dependencies are pinned in `uv.lock`. Security updates are applied
by the maintainers and tagged as patch releases.

Run `pip-audit` or `uv audit` against `requirements.txt` to check for
known vulnerabilities in your deployment.

OpenSSF Best Practices badge status:
[aevum-labs/aevum on Best Practices](https://www.bestpractices.dev/projects/12630)

## Threat model

This section describes what Aevum protects against, what it does not
protect against, and the residual risks in a production deployment.

This threat model covers `aevum-core` and `aevum-server` in a production
deployment with PostgreSQL backend, Cedar policy, and optional OPA sidecar.

### Assets

| Asset | Sensitivity | Protected by |
|---|---|---|
| Knowledge graph | High — contains personal data | Consent gates, classification ceiling |
| Episodic ledger | Critical — tamper-evident audit | Sigchain, append-only storage |
| Consent ledger | Critical — governs all access | Append-only, OR-Set semantics |
| Ed25519 signing key | Critical — enables chain forgery | KMS, process isolation |
| Application secrets (DB credentials, etc.) | High | Your secrets management |

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

Put OPA behind a load balancer with health checks. Use Cedar for all consent
policy so OPA is only needed for infrastructure policy. Consider
`AEVUM_OPA_URL` unset for deployments where Cedar suffices.

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

### What Aevum does NOT protect against

- **Compromised application code** — if your application is compromised,
  an attacker can call any Aevum function with arbitrary parameters
- **Insider threats with database access** — a DBA can modify the storage layer
- **Key theft from process memory** — without KMS, the signing key is in RAM
- **Malicious content in payloads** — Aevum stores what you ingest; scan for
  malware before ingesting documents
- **Supply chain attacks on Aevum dependencies** — mitigate with `uv audit`

### Deployment security checklist

- [ ] Ed25519 key stored in KMS, not generated at startup
- [ ] PostgreSQL credentials use least-privilege role (no superuser)
- [ ] `aevum-server` behind TLS-terminating reverse proxy
- [ ] OPA behind health check and load balancer (or Cedar-only)
- [ ] `verify_sigchain()` run on a scheduled basis (cron or CI)
- [ ] Database write access restricted to application service account only
- [ ] `AEVUM_OPA_URL` unset if OPA is not needed
- [ ] `"aevum-core[cedar]"` installed (not permissive fallback)
- [ ] Dependency audit: `uv audit` in CI pipeline

## Common security questions

**Does Aevum transmit any data to Anthropic or any external service?**

No. Aevum is a self-hosted Python library. No telemetry, no analytics, no
license checks. The only outbound connections Aevum makes are those you
explicitly configure: OPA sidecar URL and OIDC JWKS URI.

---

**Does Aevum have a SaaS component?**

No. There is no licensing server, no hosted API, and no data escrow.
Everything runs in your infrastructure.

---

**What happens if the OPA sidecar is unavailable?**

Aevum fails closed. All operations that require OPA evaluation are denied.
This is intentional — Aevum does not fall back to permissive when an
external security dependency is unavailable.

To disable OPA and use Cedar only: unset `AEVUM_OPA_URL`.

---

**What happens if Cedar is not installed?**

Aevum warns at startup and falls back to permissive consent decisions.
The five absolute barriers still fire unconditionally. In production,
install `"aevum-core[cedar]"` to avoid the permissive fallback.

---

**How is the signing key protected?**

The default `Engine()` generates a fresh Ed25519 key at startup. This key
exists only in process memory for the lifetime of the process.

For production, supply your own key from a KMS:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aevum.core.audit.sigchain import Sigchain
from aevum.core.audit.signer import InProcessSigner

key = Ed25519PrivateKey.from_private_bytes(your_kms_key_bytes)
engine = Engine(sigchain=Sigchain(signer=InProcessSigner(private_key=key, key_id="kms-key-id-1")))
```

---

**What is the attack surface of aevum-server?**

`aevum-server` is a FastAPI application. Its attack surface is:
- The five HTTP endpoints (`/ingest`, `/query`, `/review`, `/commit`, `/replay`)
- Standard FastAPI/Starlette request parsing
- Your authentication middleware (you implement this)

Aevum does not implement rate limiting, IP filtering, or DDoS protection.
Put it behind a reverse proxy with those controls.

---

**Can an attacker modify the audit trail?**

Modifications are detectable but not prevented at the storage layer.
`engine.verify_sigchain()` detects any modification because the SHA3-256
hash chain breaks at the point of modification.

For an attacker to forge a valid chain, they would need the Ed25519 private key.
Protect the key with your KMS.

---

**Does Aevum support RBAC or ABAC?**

Yes, via Cedar and OPA:
- Cedar supports attribute-based policies (ABAC) expressed in the Cedar language
- OPA supports any policy model you can express in Rego

Aevum's consent grants are themselves a form of ABAC — grants are scoped by
subject, grantee, purpose, operations, and classification ceiling.

---

**What are the CVE response times?**

Security vulnerabilities are reported via
[GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new)
(private). The target response time is 72 hours for critical vulnerabilities.
See [SECURITY.md](https://github.com/aevum-labs/aevum/blob/main/SECURITY.md).

---

**Is Aevum FedRAMP / SOC 2 certified?**

No. Aevum is open source software. Certifications apply to your deployment
of Aevum, not to the library itself. The cryptographic audit trail and
access controls support compliance programs; they do not replace them.

---

**What data does Aevum log to stderr or stdout?**

Only startup warnings (e.g., "cedarpy not installed"). No payload data,
no PII, no audit events are logged to standard output. Audit events go
exclusively to the episodic ledger.

## Multi-tenancy and isolation

Aevum supports multi-tenancy through `subject_id` and `grantee_id` scoping:
- Each tenant's data is tagged with their `subject_id` namespace
- Each tenant's agents have tenant-scoped `grantee_id` values
- Consent grants prevent cross-tenant data access

For strict process isolation between tenants, run separate Engine instances
with separate storage backends.

See [Deployment](/learn/deployment/) for storage backend configuration.

## See also

- [Architecture](/learn/architecture/) — the five absolute barriers
- [Deployment](/learn/deployment/) — production configuration
