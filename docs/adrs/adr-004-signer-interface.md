# ADR-004: Pluggable Signer interface with in-process default

Date: 2026-05-06
Status: Accepted
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

An AI agent audit trail must be "independently recorded" (21 CFR §11.10(e))
and "tamper-evident" (EU AI Act Art. 12). If the signing key lives in the
same process as the agent, a compromised agent can forge audit entries. What
is the correct key management architecture?

## Decision Drivers

- FDA 21 CFR §11.10(e) "independently record" — the audit system must be
  independent of the operator performing the recorded action
- EU AI Act Art. 12 tamper-evidence — the log must be demonstrably tamper-evident
- HIPAA §164.312(b) + 2024 NPRM — integrity verification of audit logs
- Developer experience — most deployers start with development and graduate to
  production; the design must support both without code changes

## Considered Options

1. **Pluggable Signer ABC with InProcessSigner default** (this decision)
2. Always external signing (KMS/HSM required at startup)
3. Fixed Ed25519 in-process, no pluggability

## Decision Outcome

Option 1. The Signer ABC defines the interface: `sign(digest)`,
`public_key_bytes()`, `key_id`, `provenance`. InProcessSigner is the
default — auto-generates an Ed25519 key in-process. For regulated deployments,
callers substitute VaultTransitSigner, KMSSigner, or PKCS11Signer without
any kernel code changes.

**Trust boundary matrix:**

| Deployment | Signer | Tamper-detectable | Tamper-prevented |
|---|---|---|---|
| Development | InProcessSigner (default) | Yes | No |
| Production — low regulatory risk | InProcessSigner | Yes | No |
| Production — FDA/HIPAA/EU AI Act | VaultTransitSigner or KMS | Yes | Yes |
| Production — FIPS 140-3 strict | PKCS11Signer + HSM | Yes | Yes |

**When InProcessSigner is acceptable:** systems where tamper-detection (not
tamper-prevention) is sufficient. The signing key is still unique per deployment,
the chain is still hash-chained and verifiable, and a compromised agent
would leave visible evidence of tampering once the chain is verified offline.

**When InProcessSigner is NOT acceptable:** regulated deployments under FDA
§11.10(e) where "independently record" means the audit system must be outside
the operator's control. Use VaultTransitSigner or equivalent.

### Consequences

**Good:** Zero-friction for developers; production-grade for regulated
deployments via signer substitution; VaultTransitSigner in aevum-sdk means
no cloud dependency in the kernel; provenance property in session.start makes
the trust boundary explicit and auditable.

**Bad:** Default InProcessSigner is the wrong choice for regulated production;
documentation must be very clear about this.

**Residual risk:** A developer may deploy with InProcessSigner in a regulated
environment without realising the implications. Mitigation: session.start
records key_provenance in the sigchain, so an auditor can detect this and
flag it.

## Related ADRs

- ADR-001 (single chain)
- ADR-002 (HLC — both concern the session.start declaration event)
