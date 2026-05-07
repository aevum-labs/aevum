# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (pre-release) | Current development |

Once 1.0 is released, only the most recent minor version receives security fixes.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities using GitHub Security Advisories:
https://github.com/aevum-labs/aevum/security/advisories/new

Reports are kept private until a fix is released.
We aim to respond within 48 hours and release a fix within 14 days.

Include:
- A description of the vulnerability
- Steps to reproduce
- The version of `aevum-core` affected
- Any relevant code or configuration

## Response Process

- **Acknowledgement:** within 48 hours of receipt
- **Initial assessment:** within 7 days
- **Fix or mitigation:** within 90 days for confirmed vulnerabilities
- **Public disclosure:** coordinated with the reporter after a fix is available

We follow responsible disclosure. We will not take legal action against researchers
who report vulnerabilities in good faith following this policy.

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

Aevum's security model depends on where the signing key lives relative to the
agent's trust boundary.

| Configuration | Key location | Tamper-detectable | Tamper-prevented |
|---|---|---|---|
| `InProcessSigner` (default) | Agent heap memory | ✅ | ❌ |
| `VaultTransitSigner` (aevum-sdk) | HashiCorp Vault Transit | ✅ | ✅ |
| Custom `Signer` + KMS | External KMS/HSM | ✅ | ✅ |

**For regulated deployments** (FDA 21 CFR §11.10(e), EU AI Act Article 12,
HIPAA §164.312(b) requiring independently-recorded audit trails): use an
external signer. The signing key must live outside the agent's trust boundary.

The default `InProcessSigner` provides tamper-DETECTION: any modification
to a signed event is detectable by running `verify_sigchain()`. It does NOT
provide tamper-PREVENTION: a compromised process could in principle re-sign
forged events before the chain is verified.

See [ADR-004](docs/adrs/adr-004-signer-interface.md) for the full trust-boundary
analysis.

## Complication security model

Optional complications (aevum-spiffe, aevum-publish, aevum-llm, aevum-mcp)
extend the kernel. Each complication:

- Must be explicitly installed AND approved before it activates
- Writes audit events using the kernel's sigchain (tamper-detectable)
- **Cannot** disable or bypass the five absolute barriers
- **Cannot** modify the existing chain (append-only, Barrier 4)

## Absolute barriers

The five barriers cannot be disabled by any policy, configuration, or complication:

1. **Crisis detection** — halts processing on crisis content
2. **Classification ceiling** — enforces data classification limits
3. **Consent enforcement** — requires valid consent for all operations
4. **Audit immutability** — prevents audit log modification
5. **Provenance** — records data lineage

## Cryptographic algorithms

| Component | Algorithm | Standard |
|---|---|---|
| Event signing | Ed25519 | RFC 8032, FIPS 186-5 |
| Chain hash | SHA3-256 | FIPS 202 |
| Payload hash | SHA3-256 | FIPS 202 |
| Canonicalization | RFC 8785 JCS | RFC 8785 |
| GENESIS_HASH | SHA3-256("aevum:genesis") | — |

For FIPS 140-3 strict environments: Ed25519 is FIPS 186-5 approved but not
universally available in validated cryptographic modules. See ADR-004 for the
pluggable signer path.

## External transparency (aevum-publish)

`aevum-publish` submits chain checkpoints to Sigstore Rekor v2. Note: the
current implementation targets the Rekor v1 hashedrekord submission format.
Operators using a Rekor v2 (rekor-tiles) instance should verify the API format
against [CLIENTS.md](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md)
before production use.
