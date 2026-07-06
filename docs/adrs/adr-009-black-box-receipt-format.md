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
  15: {                                      # CWT_Claims map (RFC 8392 claim numbers)
    1: "did:web:<AEVUM_ISSUER_HOST>",        #   iss: SCITT issuer URI
    2: "urn:aevum:receipt:<hash[:16]>",      #   sub: SCITT subject (compact sigchain ref)
  },
  "iat": <int unix timestamp>,              # issued-at (not part of CWT_Claims)
}
```

SCITT-profile fields per draft-ietf-scitt-architecture-22's CDDL: iss/sub are
nested under a `CWT_Claims` map at protected label 15, keyed by the RFC 8392
CWT claim registry (1=iss, 2=sub) — not flat string keys. `iat` is kept as a
flat protected field rather than moved under label 15's claim 6; only the
iss/sub nesting was confirmed against the -22 CDDL at implementation time.
See: `packages/aevum-publish/src/aevum/publish/encoder.py`.

> **Update (2026-07):** the original text-key form (`"iss"`/`"sub"` flat
> strings) shipped in Phase 1A was replaced by the nested `CWT_Claims` shape
> above before any receipt using this encoder was persisted in production or
> demo — verified against `demo.aevum.build`'s sigchain before the change, so
> no migration path was needed. Any future change to this shape, once a
> persisting service is wired to `receipt_encoder`, is a one-way format
> commitment and needs a real migration path (see the note at
> `Sigchain.__init__`'s `receipt_encoder` parameter).

### Payload

PROV-AGENT extended vocabulary (arXiv 2508.02866, ORNL/Argonne) serialized as
CBOR with deterministic key ordering. Fields cover:

- Sigchain identity (sigchain_entry_hash, sequence, prior_hash, actor)
- Model provenance (model_identity_hash, prompt_hash, retrieval_corpus_ver)
- DSSAD handoff events (handoff_type, handoff_from/to_agent_id, human_override_action)
- W3C PROV delegation chains (delegated_by, delegation_scope)
- Consent and barrier evaluations (consent_token_id, barrier_evaluations)

### Unprotected header

RFC 3161 TSA token at label 270 — `3161-ctt` per RFC 9921's IANA Considerations
(draft-ietf-cose-tsa-tst-header-parameter-08 published as RFC 9921 in Feb 2026).

**CTT, not TTC — and a deliberate departure from the RFC's own suggested fit.**
RFC 9921 defines two placements:

- **CTT** (label 270, unprotected): MessageImprint over the COSE_Sign1
  signature bytes. RFC 9921 §1.1 frames this as suited to long-term
  non-repudiation / signature validation (LTV-style) use cases.
- **TTC** (label 269, protected): MessageImprint over the payload, timestamped
  *before* signing. RFC 9921 §1.1 frames this as the better fit for
  SCITT-style transparent-statement notarization — which is closer to what
  Aevum's receipts are for.

Aevum uses **CTT** anyway. TTC requires the TSA round-trip to complete and be
embedded in the protected header *before* the Ed25519 signature is computed.
That conflicts with the sigchain's existing "a TSA outage never blocks a
write" circuit-breaker contract (see `aevum.core.tsa.TSAClient`): going TTC
would either block receipt issuance on TSA availability, or make the
protected-header shape non-deterministic depending on whether the TSA
responded in time — worse than either mode alone. CTT preserves the existing
contract exactly: the token is fetched non-blockingly *after* signing and
simply omitted from the unprotected header on any TSA failure.
See `packages/aevum-publish/src/aevum/publish/encoder.py`'s module docstring
for the same reasoning in code.

**Verification:** `aevum.verify._core.verify_receipt_tsa` independently
reimplements the CTT check (imprint + token signature + chain to a pinned
`tsa_root_cert`) with no import of `aevum.publish` or `aevum.core` — same
independence contract as the Merkle/STH verifiers in that module. Wired into
`aevum verify-receipt`, which reports `verified` / `FAILED` / absent instead
of only the token's byte length.

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

- CTT was chosen over TTC to preserve the non-blocking TSA circuit-breaker
  contract, a deliberate departure from RFC 9921 §1.1's own suggested best
  fit for SCITT-style notarization (TTC). Revisiting this later means moving
  the TSA call before signing and accepting either a blocking dependency on
  TSA availability or a non-deterministic protected-header shape.
- `iat` is not nested under the CWT_Claims map (label 15) the way iss/sub
  are — only the iss/sub nesting was confirmed against the -22 CDDL. Worth
  re-checking whether `iat` (RFC 8392 claim 6) belongs under label 15 too.
- SCITT TS submission deferred until ScrAPI (draft-ietf-scitt-scrapi) stabilizes
- RekorV2Backend failure degrades I6 (CRASH_PROTECTED) to "best effort"; logged as warning
- `aevum.core.ambient.AmbientContextEncoder` still uses the pre-update format
  (flat iss/sub, placeholder unprotected label 9, payload-hashed TSA token) —
  it wasn't in scope for the 2026-07 update and now drifts from
  `ReceiptEncoder`'s format until a follow-up applies the same fix there.

### Open questions

- When should `verify-receipt` and `verify` be unified? **Proposed: never** —
  they serve different purposes (forensic receipt verification vs. session replay).
- Should `AmbientContextEncoder` (aevum-core) be migrated to the same CTT +
  CWT_Claims format as `ReceiptEncoder`? Same one-way-format caveat applies
  once any service persists its output.

## Related ADRs

- ADR-001 (Single sigchain — the chain events that receipts attest)
- ADR-004 (Signer interface — the Ed25519 key used to sign receipts)
- ADR-007 (Transparency log — Rekor v2 as the external witness backend)
- ADR-008 (Multi-agent correlation — cross-chain references verified via Rekor)
