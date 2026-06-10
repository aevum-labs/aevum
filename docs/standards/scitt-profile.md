# Aevum SCITT Profile for AI Agent Governance Statements

**Version:** 0.1 (Draft)
**Base specification:** draft-ietf-scitt-architecture-22
**Date:** 2026-05-25

---

## 1. Scope

This profile specifies how to use SCITT Signed Statements to record AI agent
governance events in compliance with:

- **EU AI Act** Article 12 (automatic logging for high-risk AI)
- **ISO/IEC 42001:2023** Annex A.6.2.8 (event log recording by lifecycle phase)
- **NIST SP 800-53 Rev 5** AU-10 (non-repudiation, High baseline)

This document positions Aevum as a SCITT *profile* — a set of conventions for
using SCITT to record AI agent governance statements. It is an application
profile analogous to how ACME (RFC 8555) profiles JOSE for certificate issuance.
Aevum is not a fork or competitor to SCITT; it applies SCITT to a specific domain.

**Relationship to the SCITT architecture:** In SCITT terms, Aevum is a
*Statement Author* that produces *Signed Statements*. The `RekorV2Backend`
provides partial SCITT coverage (Rekor is RFC 6962-style but not a SCITT
Transparency Service). The `ScittTsBackend` will provide full SCITT TS
coverage when ScrAPI (draft-ietf-scitt-scrapi) becomes an RFC.

---

## 2. Signed Statement Structure

Each Aevum receipt is a SCITT Signed Statement encoded as COSE_Sign1 (RFC 9052).

### 2.1 Wire format

```
COSE_Sign1 = [
  protected_bstr,    # bstr-wrapped CBOR map (see §2.2)
  unprotected_map,   # plain CBOR map (see §2.3)
  payload_bstr,      # AevumReceipt CBOR bytes (see §3)
  signature_bstr,    # Ed25519 over SHA3-256(Sig_Structure)
]
```

Sig_Structure per RFC 9052 §4.4:
```
["Signature1", protected_bstr, b"", payload_bstr]
```

### 2.2 Protected header

| Key | Value | Note |
|-----|-------|------|
| `1` (alg) | `-8` | EdDSA/Ed25519 (RFC 9053) |
| `3` (content_type) | `"application/aevum-receipt+cbor"` | MIME type |
| `4` (kid) | `b"aevum-issuer-v1"` | Key identifier |
| `"iss"` | `"did:web:<AEVUM_ISSUER_HOST>"` | SCITT issuer URI |
| `"sub"` | `"urn:aevum:receipt:<sigchain_entry_hash[:16]>"` | SCITT subject |
| `"iat"` | `<int unix timestamp>` | Issued-at |

> **Draft status:** draft-ietf-scitt-architecture-22 §4.1 does not yet assign
> integer labels for `iss` and `sub`. Text key strings are used until integer
> labels are standardized. When the draft publishes as an RFC, Aevum will
> update to the assigned integer labels in a backward-compatible migration
> (see §7 for the migration plan).

### 2.3 Unprotected header

| Key | Value | Note |
|-----|-------|------|
| `9` (tst) | RFC 3161 TST bytes | Present when TSA is configured |

Label 9 per draft-ietf-cose-tsa-tst-header-parameter-08 (label TBD; using 9
as placeholder until RFC publishes).

---

## 3. PROV-AGENT Vocabulary Extension

The payload is an `AevumReceipt` object serialized as deterministically-ordered
CBOR. Fields map to PROV-AGENT (arXiv 2508.02866, ORNL/Argonne research) and
DSSAD (UNECE WP.29 UN R157) concepts.

### 3.1 Sigchain identity fields

| Aevum field | PROV-AGENT concept | Aevum usage |
|-------------|-------------------|-------------|
| `sigchain_entry_hash` | `prov:Entity` identifier | SHA3-256 over event identity fields |
| `action` | `prov:Activity` label | Agent action type |
| `principal` | `prov:Agent` | Actor identity |
| `prior_hash` | `prov:wasDerivedFrom` | Previous sigchain entry |
| `occurred_at` | `prov:startedAtTime` | ISO 8601 timestamp |
| `sequence` | monotonic counter | Ensures no gaps |

### 3.2 Model provenance fields (PROV-AGENT §4)

| Aevum field | PROV-AGENT concept | Aevum usage |
|-------------|-------------------|-------------|
| `model_identity_hash` | model agent identity | SHA3-256 of model ID string |
| `prompt_hash` | input provenance | SHA3-256 of prompt |
| `retrieval_corpus_ver` | RAG corpus version | "NONE" if no retrieval |
| `policy_version` | governance context | Policy bundle version |
| `tool_allowlist_hash` | tool authorization set | SHA3-256 of allowed tools |

### 3.3 DSSAD handoff fields (UNECE WP.29 UN R157 mapping)

| Aevum field | DSSAD event type | Aevum usage |
|-------------|-----------------|-------------|
| `handoff_type` | Transition/takeover | `TRANSITION_DEMAND`, `TAKEOVER`, etc. |
| `handoff_from_agent_id` | Exiting system identity | Agent handing off control |
| `handoff_to_agent_id` | Receiving system identity | Agent receiving control |
| `human_override_action` | Human intervention event | Override description |

### 3.4 Delegation fields (W3C PROV actedOnBehalfOf)

| Aevum field | W3C PROV concept | Aevum usage |
|-------------|-----------------|-------------|
| `delegated_by` | `prov:actedOnBehalfOf` | Delegating agent identity |
| `delegation_scope` | delegation scope label | What authority was delegated |

---

## 4. Seven Invariants

The Aevum receipt layer enforces seven formal invariants defined in
`packages/aevum-core/src/aevum/core/invariants.py`.
See `docs/architecture/invariants.md` for proof sketches and failure mode analysis.

| Invariant | Scope | Status in v0.7.0 |
|-----------|-------|------------------|
| I1-APPEND_ONLY | Receipt store | Enforced (frozen dataclass + append-only ledger) |
| I2-COMPLETENESS | Signed Statement | Enforced (encoder wired into sigchain) |
| I3-INTEGRITY | Signed Statement | Enforced (Ed25519 + SHA3-256) |
| I4-BOUNDARY_ENFORCEMENT | Policy layer | Enforced (Cedar + five barriers) |
| I5-MONOTONIC_SEQUENCE | Sigchain | Enforced (atomic counter increment) |
| I6-CRASH_PROTECTED | Transparency backend | Partial (RekorV2Backend; full with WORM storage) |
| I7-SCITT_REGISTERED | Transparency Service | Aspirational; ScittTsBackend stub pending ScrAPI RFC |

Invariants I1–I5 apply to every Signed Statement.
I6 applies when `RekorV2Backend` is configured.
I7 is not satisfied in v0.7.0 (ScittTsBackend raises `NotImplementedError`).

---

## 5. Verification Procedure

### 5.1 Using the Aevum CLI

```bash
aevum verify-receipt <receipt_file>
```

This command:
1. Decodes the COSE_Sign1 array from CBOR
2. Verifies `alg = -8` (EdDSA/Ed25519)
3. Reconstructs `Sig_Structure = ["Signature1", protected_bstr, b"", payload_bstr]`
4. Computes `SHA3-256(Sig_Structure)` and verifies Ed25519 signature
5. Decodes the payload as `AevumReceipt` and prints a human-readable summary

Exit code 0 = signature valid. Exit code 1 = invalid or missing signature.

### 5.2 Offline verification (no Aevum server)

Any party with the issuer's Ed25519 public key can verify receipts offline:

```python
import cbor2, hashlib, nacl.signing

raw = open("receipt.cbor", "rb").read()
cose = cbor2.loads(raw)
protected_bstr, unprotected, payload_bstr, sig_bytes = cose

sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
digest = hashlib.sha3_256(sig_structure).digest()

pub_key_bytes = open("aevum.pub", "rb").read()  # 32-byte Ed25519 public key
verify_key = nacl.signing.VerifyKey(pub_key_bytes)
verify_key.verify(digest, bytes(sig_bytes))      # raises BadSignatureError on failure
```

### 5.3 FRE 902(13) admissibility

See `docs/legal/fre-902-13-certification-template.md` for the qualified person
certification template enabling FRE 902(13) self-authentication in US federal court.

The certification attests that:
- Receipts were generated automatically by the Aevum audit and evidence layer
- The Ed25519 signature process is described in sufficient detail for the court
- Tampering is detectable via `aevum verify-receipt <receipt_file>`

---

## 6. Transparency Service Requirements

### 6.1 NullBackend (dev only)

Returns a deterministic UUID derived from `SHA3-256(receipt_cbor)[:16]`.
No network calls. No third-party verification possible. **Not for production.**

### 6.2 RekorV2Backend (current production recommendation)

Submits the COSE_Sign1 receipt to Rekor v2 (sigstore/rekor-tiles) as a
`hashedrekord` entry using `SHA-256(receipt_cbor)` as the artifact hash.

- Configure via `AEVUM_REKOR_URL` (S-13: no hardcoded URLs)
- Returns the Rekor log entry UUID
- Provides external witnessing but is NOT a SCITT Transparency Service

**Recommended Maximum Merge Delay (MMD):** ≤24 hours for production deployments.
A shorter MMD (≤1 hour) is recommended for regulated environments (FDA GxP,
EU AI Act high-risk).

### 6.3 ScittTsBackend (future)

Stub that raises `NotImplementedError`. Will implement ScrAPI
(draft-ietf-scitt-scrapi) once the draft becomes an RFC.

When activated, this backend will:
- Submit Signed Statements to a SCITT Transparency Service via ScrAPI
- Return an SCITT inclusion proof (receipt in the SCITT sense)
- Satisfy I7-SCITT_REGISTERED

---

## 7. Draft Status and Known Limitations

### 7.1 TBD labels

| Standard | TBD item | Expected resolution |
|----------|----------|---------------------|
| draft-ietf-scitt-architecture-22 §4.1 | `iss`, `sub` integer labels | When draft → RFC |
| draft-ietf-cose-tsa-tst-header-parameter-08 | TST header label (using 9) | When draft → RFC |

**Update locations when labels are assigned:**
- `packages/aevum-publish/src/aevum/publish/encoder.py` (code comment marks the location)
- `packages/aevum-core/src/aevum/core/ambient.py` (same pattern)
- This document (§2.2 and §2.3 tables)

### 7.2 Compatibility commitment

Aevum will maintain backward compatibility on the Signed Statement wire format.
Label updates will be versioned:

1. Add new integer labels alongside existing text keys (one version)
2. Deprecate text keys (one version)
3. Remove text keys (next major version)

Existing receipts with text keys will remain verifiable throughout this migration.

---

## 8. Relationship to Existing Standards

### 8.1 EU AI Act Art. 12

| Art. 12 requirement | Aevum implementation |
|--------------------|---------------------|
| Art. 12(1) Automatic recording over system lifetime | Sigchain + session.start |
| Art. 12(2)(a) Recording purposes and systems involved | AuditEvent.payload + episode_id |
| Art. 12(2)(b) Identify persons responsible | principal + delegated_by |
| Art. 12(2)(c) Input data used | prompt_hash + retrieval_corpus_ver |
| Art. 12(3) Biometric-specific retention | Deployer-extended AuditEvent.payload |

### 8.2 ISO/IEC 42001:2023

| Control | Aevum primitive |
|---------|----------------|
| A.6.2.8 Event log recording by lifecycle phase | Sigchain (all phases) |
| A.6.2.6 AI system monitoring | review() + replay() |

Full ISO/IEC 42001 control mapping: `docs/learn/compliance-mapping.md`

### 8.3 NIST SP 800-53 AU-10

AU-10 (Non-repudiation, High baseline) requires the ability to link an action
to the entity that performed it in a manner that cannot be denied.

Aevum satisfies AU-10 via:
- Ed25519 signature over SHA3-256 of the canonical payload (cryptographic non-repudiation)
- PROV-AGENT `principal` field identifying the acting agent
- External transparency log witness (Rekor v2) providing third-party corroboration

### 8.4 FRE 902(13)

FRE 902(13) (Records Generated by an Electronic Process or System) permits
self-authentication of electronic evidence via a certification from a qualified
person. The Advisory Committee Note explicitly endorses hash-value comparison.

Ed25519 + SHA3-256 receipt verification provides non-repudiation equivalent to
or stronger than the hash-comparison process explicitly endorsed in the Advisory
Committee notes. See `docs/legal/fre-902-13-certification-template.md`.

---

## 9. Reference Implementation

**PyPI package:** `aevum-publish`
**Verification CLI:** `aevum verify-receipt <receipt_file>`
**Source:** `packages/aevum-publish/src/aevum/publish/encoder.py`

### 9.1 Example: generate and verify a receipt

```python
from aevum.core.receipt import AevumReceipt
from aevum.publish.encoder import ReceiptEncoder
from aevum.core.signing import DualSigner

signer = DualSigner.generate()
enc = ReceiptEncoder(signer=signer, dev_mode=True)

receipt = AevumReceipt(
    sigchain_entry_hash="a" * 64,
    action="tool.call",
    principal="agent-001",
    prior_hash="b" * 64,
    occurred_at="2026-05-25T12:00:00Z",
    agent_id="agent-001",
    sequence=1,
    aevum_version="0.7.0",
    model_identity_hash="UNKNOWN",
    prompt_hash="UNKNOWN",
    retrieval_corpus_ver="NONE",
    policy_version="v1",
    tool_allowlist_hash="UNKNOWN",
    handoff_type=None,
    handoff_from_agent_id=None,
    handoff_to_agent_id=None,
    human_override_action=None,
    delegated_by=None,
    delegation_scope=None,
    consent_token_id=None,
    barrier_evaluations={},
)
cose_bytes = enc.encode(receipt)
```

### 9.2 Example receipt (decoded)

Protected header (decoded from bstr):
```json
{
  "1": -8,
  "3": "application/aevum-receipt+cbor",
  "4": "YWV2dW0taXNzdWVyLXYx",
  "iss": "did:web:aevum.local",
  "sub": "urn:aevum:receipt:aaaaaaaaaaaaaaaa",
  "iat": 1748168400
}
```

Payload fields (decoded from CBOR):
```json
{
  "action": "tool.call",
  "agent_id": "agent-001",
  "aevum_version": "0.7.0",
  "barrier_evaluations": {},
  "consent_token_id": null,
  "delegated_by": null,
  "delegation_scope": null,
  "handoff_from_agent_id": null,
  "handoff_to_agent_id": null,
  "handoff_type": null,
  "human_override_action": null,
  "model_identity_hash": "UNKNOWN",
  "occurred_at": "2026-05-25T12:00:00Z",
  "policy_version": "v1",
  "principal": "agent-001",
  "prior_hash": "bbbb...bbbb",
  "prompt_hash": "UNKNOWN",
  "retrieval_corpus_ver": "NONE",
  "sequence": 1,
  "sigchain_entry_hash": "aaaa...aaaa",
  "tool_allowlist_hash": "UNKNOWN"
}
```
