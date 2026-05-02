# Security Architecture

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

See [The Five Barriers](../concepts/five-barriers.md).

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

## Multi-tenancy

Aevum supports multi-tenancy through `subject_id` and `grantee_id` scoping:
- Each tenant's data is tagged with their `subject_id` namespace
- Each tenant's agents have tenant-scoped `grantee_id` values
- Consent grants prevent cross-tenant data access

For strict process isolation between tenants, run separate Engine instances
with separate storage backends.

## Secret management

Aevum itself has no secrets to manage except the Ed25519 signing key.
For production:
1. Generate the key in your KMS
2. Pass it to `Engine(sigchain=Sigchain(private_key=your_key))`
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
