# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| 0.3.x   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: security@aevum.build

Response within 72 hours. Confirmed vulnerabilities addressed in a patch release.
Credit given in release notes unless you prefer anonymity.

## Security Architecture

Aevum's key security properties:

- SHA-256 Merkle chain audit trail — tamper-evident, cannot be silently altered
- Ed25519-signed principles verified at boot (runtime verification in Phase 1)
- Five absolute barriers enforced via Cedar forbid policies (non-bypassable)
- Append-only audit trail enforced at storage layer (no UPDATE or DELETE)
- Consent gate verified before every context traversal
- Crisis detection runs before any graph write

Full threat model: [THREAT_MODEL.md](THREAT_MODEL.md)

## Supply Chain

- pip-audit on every CI push
- OpenSSF Scorecard badge — Phase 9
- CycloneDX SBOM on every release — Phase 9
- PyPI Trusted Publishing (OIDC, no stored API keys) — Phase 9

## Signing Key Trust Boundary

Aevum's security model depends on where the signing key lives relative to the
agent's trust boundary.

| Configuration | Key location | Tamper-detectable | Tamper-prevented |
|---|---|---|---|
| `InProcessSigner` (default) | Agent heap memory | ✅ | ❌ |
| `VaultTransitSigner` | HashiCorp Vault Transit | ✅ | ✅ |
| `PKCS11Signer` | HSM / hardware key | ✅ | ✅ |

**For regulated deployments** (FDA 21 CFR §11.10(e), EU AI Act Article 12,
HIPAA §164.312(b) requiring independently-recorded audit trails): use an
external signer. The signing key must live outside the agent's trust boundary.

See [ADR-004](docs/adrs/adr-004-signer-interface.md) for the full trust-boundary
analysis.

## Absolute Barriers

The five barriers cannot be disabled by any policy, configuration, or complication:

1. **Crisis detection** — halts processing on crisis content
2. **Classification ceiling** — enforces data classification limits
3. **Consent enforcement** — requires valid consent for all operations
4. **Audit immutability** — prevents audit log modification
5. **Provenance** — records data lineage

## Cryptographic Algorithms

| Component | Algorithm | Standard |
|---|---|---|
| Event signing | Ed25519 | RFC 8032, FIPS 186-5 |
| Chain hash | SHA3-256 | FIPS 202 |
| Payload hash | SHA3-256 | FIPS 202 |
| Canonicalization | RFC 8785 JCS | RFC 8785 |
| Principles signing | Ed25519 | RFC 8032 |
