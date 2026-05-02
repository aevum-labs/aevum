# Security FAQ

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

key = Ed25519PrivateKey.from_private_bytes(your_kms_key_bytes)
engine = Engine(sigchain=Sigchain(private_key=key, key_id="kms-key-id-1"))
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
