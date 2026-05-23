# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| 0.5.x   | No        |
| 0.4.x   | No        |

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

## Trademark Status

Trademark search for "Aevum": TESS (USPTO) Class 9 and 42, and EUIPO
equivalent, is required before the first public PyPI release under the
`aevum-core` name. **Status: pending maintainer action.** No filing has
been made. This is a manual step — the maintainer must initiate the search
and record the outcome here before the 1.0.0 release.

## EAR §742.15 Export Notification (D-19)

**Status: TEMPLATE PRODUCED — AWAITING MAINTAINER REVIEW AND FILING**

Aevum-core uses Ed25519 digital signatures and SHA3-256 hashing. These are
encryption items subject to EAR (Export Administration Regulations) §742.15.
Open-source cryptographic software qualifies for the License Exception ENC
(15 C.F.R. §740.17(b)(4)) provided a one-time notification is submitted to
BIS (Bureau of Industry and Security) and NSA.

> **Maintainer action required:** Review the template below. If the notification
> has already been filed (e.g., from a prior release), record the date and BIS
> reference number in this section and delete the template. If not yet filed,
> complete and submit the template before the next public release that includes
> cryptographic functionality.
>
> **Do not file without maintainer review.** The template below is for review
> only; it has not been submitted.

### Filing requirements

Per 15 C.F.R. §742.15(b) and §740.17(b)(4):

1. Submit the notification by email to: crypt@bis.doc.gov and enc@nsa.gov
2. The subject line must read: "NOTIFICATION OF INTERNET DOWNLOAD SITE FOR
   ENCRYPTION SOURCE CODE OR OBJECT CODE"
3. Submit once, before or at the time of public release.
4. Retain a copy of the submission confirmation.

### Completed template (for maintainer review)

```
To: crypt@bis.doc.gov, enc@nsa.gov
Subject: NOTIFICATION OF INTERNET DOWNLOAD SITE FOR ENCRYPTION SOURCE CODE
         OR OBJECT CODE

In accordance with 15 C.F.R. §742.15(b) and §740.17(b)(4), Aevum Labs
hereby notifies BIS and NSA of the availability of open-source encryption
software at the following URL:

  https://github.com/aevum-labs/aevum

Product name: aevum-core
Version: 0.6.0 (and all subsequent versions)
Maintainer: Aevum Labs
Contact email: security@aevum.build

Description of encryption functionality:
  aevum-core uses the following cryptographic algorithms for audit chain
  integrity and digital signing:
  - Ed25519 digital signatures (RFC 8032) for AuditEvent signing
  - SHA3-256 (FIPS 202) for hash chaining and payload integrity
  - SHA-256 (FIPS 180-4) for Rekor transparency log submission

  These algorithms are used exclusively for:
  - Authentication of audit records (signing, not encryption of payload)
  - Data integrity verification (hash chains)
  - External transparency log anchoring

  aevum-core does NOT implement its own cryptographic algorithms. It uses
  the following open-source libraries:
  - cryptography (pyca/cryptography) — Apache-2.0, uses OpenSSL under the hood
  - hashlib (Python standard library) — uses system OpenSSL or libtomcrypt

License: Apache-2.0
Source code URL: https://github.com/aevum-labs/aevum
PyPI: https://pypi.org/project/aevum-core/

This software is publicly available at no charge. It is not subject to
EAR99 because it performs encryption; however, it qualifies for License
Exception ENC under 15 C.F.R. §740.17(b)(4) as publicly available
encryption source code.

Submitted by: [MAINTAINER NAME]
Date: [DATE OF SUBMISSION]
```

### After filing

Once submitted:
1. Replace the template above with the filing date and BIS reference number.
2. Update the "Supported Versions" table if applicable.
3. Add a note to CHANGELOG.md under the relevant release.
