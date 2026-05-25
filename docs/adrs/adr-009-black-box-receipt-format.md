# ADR-009: Black Box Receipt Format — COSE_Sign1, PROV-AGENT, SCITT Profile

Date: 2026-05-25
Status: Accepted
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

Aevum needed a portable, verifiable, third-party-readable receipt format for
sigchain events. The design must satisfy six properties derived from cross-domain
analysis of FDR (aviation), VDR (maritime), EDR/DSSAD (automotive), and
21 CFR Part 11 (medical) black box requirements:

1. **Mandatory recording** — every agent action produces exactly one receipt
2. **Fixed parameter set** — the receipt schema is frozen at Phase 1 (S-12)
3. **Tamper-evident storage** — Ed25519 signature over SHA3-256 of the payload
4. **Standardized format** — readable by any third party with the issuer public key
5. **Chain-of-custody to independent investigator** — transparency log inclusion proof
6. **Retention period compliance** — append-only; compatible with all major frameworks

Existing options considered:

| Option | Why rejected |
|--------|-------------|
| Raw JSON + HMAC | Operator-controlled key; no third-party verification |
| W3C Verifiable Credentials | JSON-LD overhead; no native binary efficiency |
| Sigstore bundle format | Certificate-centric, not payload-centric |
| COSE_Sign1 (RFC 9052) | IETF standard, binary-efficient, native SCITT compat |

## Decision Drivers

- FRE 902(13) self-authentication path for US federal court admissibility
- EU AI Act Art. 12 mandatory recording for high-risk AI systems
- ISO/IEC 42001 Annex A.6.2.8 event log recording
- NIST SP 800-53 AU-10 non-repudiation (High baseline)
- SCITT (draft-ietf-scitt-architecture-22) ecosystem alignment
- Binary efficiency: CBOR receipts are 40–60% smaller than equivalent JSON-LD

## Decision Outcome

**COSE_Sign1 (RFC 9052) over CBOR (RFC 8949)** with the following structure:

### Protected header

```
{
  1: -8,                                    # alg: EdDSA/Ed25519 (RFC 9053)
  3: "application/aevum-receipt+cbor",      # content_type
  4: b"aevum-issuer-v1",                    # kid
  "iss": "did:web:<AEVUM_ISSUER_HOST>",     # SCITT issuer URI
  "sub": "urn:aevum:receipt:<hash[:16]>",  # SCITT subject (compact sigchain ref)
  "iat": <int unix timestamp>,              # issued-at
}
```

SCITT-profile fields (iss, sub, iat) per draft-ietf-scitt-architecture-22 §4.1.
Integer labels for iss/sub are TBD in the draft; text keys used until standardized.
See: `packages/aevum-publish/src/aevum/publish/encoder.py` for the code comment
marking the update location when integer labels are assigned.

### Payload

PROV-AGENT extended vocabulary (arXiv 2508.02866, ORNL/Argonne) serialized as
CBOR with deterministic key ordering. Fields cover:

- Sigchain identity (sigchain_entry_hash, sequence, prior_hash, actor)
- Model provenance (model_identity_hash, prompt_hash, retrieval_corpus_ver)
- DSSAD handoff events (handoff_type, handoff_from/to_agent_id, human_override_action)
- W3C PROV delegation chains (delegated_by, delegation_scope)
- Consent and barrier evaluations (consent_token_id, barrier_evaluations)

### Unprotected header

RFC 3161 TSA token in label 9 per draft-ietf-cose-tsa-tst-header-parameter-08
(label TBD; using integer 9 as placeholder until RFC publishes).

### Transparency backend

Pluggable via `TransparencyBackend` protocol:

| Backend | Use case |
|---------|----------|
| `NullBackend` | Dev mode only; deterministic UUID; no external calls |
| `RekorV2Backend` | Current production recommendation; Sigstore Rekor v2 |
| `ScittTsBackend` | Future; stub raises `NotImplementedError` until ScrAPI stabilizes |

### CLI command name

`aevum verify-receipt` (not `aevum verify`) due to a pre-existing
`aevum verify <session_id>` command that performs session replay verification.
The two commands serve distinct purposes and must remain separate:

- `aevum verify <session_id>` — replay-based Merkle root verification of a session
- `aevum verify-receipt <file>` — forensic COSE_Sign1 receipt verification

### Implementation choices

- **cbor2 6.1.1** added as a direct runtime dependency of aevum-core and aevum-publish.
- **pycose was NOT adopted** — manual COSE_Sign1 construction with cbor2 gives
  precise control over the wire format and avoids an additional dependency with its
  own interface stability risk.
- **Ed25519 via PyNaCl** — p50=0.029ms per receipt (see docs/learn/performance.md).
  sign-every-entry architecture locked; batch Merkle-root signing not required.

## Consequences

### Positive

- Any third party with the issuer public key can verify receipts offline
- SCITT-compatible envelopes survive Transparency Service ecosystem evolution
- PROV-AGENT fields enable deterministic multi-agent decision chain reconstruction
- DSSAD handoff fields provide "why it happened" complement to "what happened"
- FRE 902(13) self-authentication via Ed25519 + SHA3-256 (Advisory Committee Note)
- Binary-efficient: CBOR receipts are significantly smaller than JSON-LD VCs

### Negative / risks

- draft-ietf-cose-tsa-tst-header-parameter-08 label TBD; one rename expected at RFC
- draft-ietf-scitt-architecture-22 iss/sub labels TBD; update when standardized
- SCITT TS submission deferred until ScrAPI (draft-ietf-scitt-scrapi) stabilizes
- RekorV2Backend failure degrades I6 (CRASH_PROTECTED) to "best effort"; logged as warning

### Open questions

- When should `verify-receipt` and `verify` be unified? **Proposed: never** —
  they serve different purposes (forensic receipt verification vs. session replay).
- When SCITT assigns integer labels for iss/sub: migrate in a backward-compatible way
  (add new integer labels alongside text keys for one version, then remove text keys).

## Related ADRs

- ADR-001 (Single sigchain — the chain events that receipts attest)
- ADR-004 (Signer interface — the Ed25519 key used to sign receipts)
- ADR-007 (Transparency log — Rekor v2 as the external witness backend)
- ADR-008 (Multi-agent correlation — cross-chain references verified via Rekor)
