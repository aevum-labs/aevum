---
description: "Aevum security policy: vulnerability reporting, signing key
trust boundary, complication security model, and cryptographic algorithm
reference."
---

# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (pre-release) | Current development |

Once 1.0 is released, only the most recent minor version receives security fixes.

## Reporting a vulnerability

If you discover a security vulnerability in Aevum, please report it
via [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new)
rather than a public issue.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

We aim to acknowledge reports within 5 business days and to provide an
initial assessment within 14 days.

## Response process

- **Acknowledgement:** within 5 business days of receipt
- **Initial assessment:** within 14 days
- **Fix or mitigation:** within 90 days for confirmed vulnerabilities
- **Public disclosure:** coordinated with the reporter after a fix is available

We follow responsible disclosure. We will not take legal action against
researchers who report vulnerabilities in good faith following this policy.

## Scope

The following are in scope:

- `aevum-core` and all packages in the `aevum-labs/aevum` monorepo
- The Aevum protocol specification (`aevum-labs/aevum-spec`)
- The conformance test suite (`aevum-labs/aevum-conformance`)

The following are out of scope:

- Vulnerabilities in dependencies (report to the dependency maintainer)
- Vulnerabilities that require physical access to the system
- Social engineering attacks

---

## Signing key trust boundary

Aevum's security model depends on where the signing key lives relative
to the agent's trust boundary.

| Configuration | Key location | Tamper-detectable | Tamper-prevented |
|---|---|---|---|
| `InProcessSigner` (default) | Agent heap memory | ✅ | ❌ |
| `VaultTransitSigner` | HashiCorp Vault Transit | ✅ | ✅ |
| `PKCS11Signer` | HSM / hardware key | ✅ | ✅ |

**For regulated deployments** (FDA 21 CFR §11.10(e), EU AI Act Article 12,
HIPAA §164.312(b) requiring tamper-evident audit trails): use an external
signer. The signing key must be outside the agent's trust boundary.

The default `InProcessSigner` provides tamper-DETECTION: any modification
to a signed event is detectable by running `verify_sigchain()`. It does NOT
provide tamper-PREVENTION: a compromised process could in principle re-sign
forged events before the chain is verified.

See [ADR-004](/adrs/adr-004-signer-interface/) for the full
trust-boundary analysis.

## Complication security model

Optional complications (aevum-spiffe, aevum-publish, aevum-llm, aevum-mcp)
extend the kernel. Each complication:

- Must be explicitly installed AND approved before activating
- Writes audit events using the kernel's sigchain (tamper-evident)
- Cannot disable or bypass the five absolute barriers
- Cannot modify the existing chain (append-only)

## Absolute barriers

The five barriers cannot be disabled or bypassed by any policy, configuration,
or complication:

1. **Crisis detection** — halts on dangerous content
2. **Classification ceiling** — enforces data classification limits
3. **Consent enforcement** — requires valid consent for all operations
4. **Audit immutability** — prevents audit log modification
5. **Provenance** — records data lineage

These are kernel-enforced, not policy-controlled. A misconfigured Cedar or
OPA policy cannot override them.

## Cryptographic algorithms

| Component | Algorithm | Standard |
|---|---|---|
| Event signing | Ed25519 | RFC 8032, FIPS 186-5 |
| Chain hash | SHA3-256 | FIPS 202 |
| Payload hash | SHA3-256 | FIPS 202 |
| Canonicalization | RFC 8785 JCS | RFC 8785 |
| GENESIS_HASH | SHA3-256("aevum:genesis") | — |

For FIPS 140-3 strict environments: Ed25519 is FIPS 186-5 approved but
not yet in all validated cryptographic modules. Use `VaultTransitSigner`
with a FIPS-validated Vault deployment, or implement a custom `Signer`
against a FIPS 140-3 validated PKCS#11 module.

## External transparency

With `aevum-publish`, chain checkpoints are submitted to Sigstore Rekor v2.
Note: the Rekor v2 (rekor-tiles) hashedrekord API format should be verified
against [CLIENTS.md](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md)
before production use. The submission format in the current implementation
targets the Rekor v1 hashedrekord spec.

## See also

- [Architecture](/learn/architecture/) — the five absolute barriers
- [ADR-004](/adrs/adr-004-signer-interface/) — signer trust-boundary analysis
- [Deployment Patterns](/learn/deployment-patterns/) — signing key tier by deployment
