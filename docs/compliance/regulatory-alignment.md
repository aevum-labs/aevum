---
description: "Aevum regulatory alignment — external capability claims derived from the internal control map. Every claim is capability-framed, traces to a verified internal row, and avoids compliance verdicts. Not legal advice."
---

# Aevum Regulatory Alignment

**Audience:** Customers, procurement reviewers, and compliance officers evaluating Aevum's capabilities in regulated contexts.

> **Derived from the internal control map.** Every claim on this page traces to a row in [control-mapping.md](./control-mapping.md) tagged `verified (primary source)`. No claim on this page is based on an `UNVERIFIED` internal row. For the complete internal map — including UNVERIFIED framework rows, explicit gaps, and the follow-up flag list — see [control-mapping.md](./control-mapping.md).

---

## Disclaimer

*Aevum is a tool that helps firms meet recordkeeping obligations; it does not itself constitute compliance, which depends on the firm's policies, procedures, and deployment. Not legal advice.*

Aevum does not assert that use of this library makes a firm "17a-4 compliant," "SEC-approved," "court-admissible," or compliant with any other regulation. Regulatory compliance is a determination made by the firm's compliance and legal counsel based on their specific deployment, policies, and context — not a property any library can assert.

Aevum Labs has not undergone a SOC 2 examination or a commissioned third-party penetration test, and Aevum is maintained as a solo open-source research project. These are stated plainly so reviewers can weigh them; see the [SOC 2 Evidence Guide](./soc2.md) for how Aevum supports a deployer's own SOC 2 program.

---

## SEC Rule 17a-4(f)(2)(i)(A) — Audit-Trail Alternative

*Internal map rows: 17a-4(f)(2)(i)(A) elements (1)–(4) and (f)(2)(iv) — all tagged `verified (primary source)` in [control-mapping.md](./control-mapping.md).*

Aevum is designed to support the **audit-trail alternative** to WORM storage under SEC Rule 17a-4(f)(2)(i)(A) (17 CFR § 240.17a-4, as amended by SEC Release No. 34-96034, 2022 amendments). The four required elements of the audit-trail alternative correspond to specific Aevum capabilities:

**Element (1) — Modifications and deletions captured**
*(internal map row: f)(2)(i)(A)(1))*

Aevum produces an append-only, cryptographically-chained ledger. There is no delete or overwrite operation. Modifications are new appended events; the prior state remains in the chain. RFC 6962-style Merkle consistency proofs — verifiable by the open-source `aevum-verify` package — enable detection of any historical rewrite. Barrier 4 (`ImmutableLedgerError`) unconditionally prevents in-place deletion at the application layer with no configuration path to disable it.

**Element (2) — Date and time of every action**
*(internal map row: f)(2)(i)(A)(2))*

Every record carries a system timestamp. Records optionally carry an RFC 3161 trusted timestamp obtained from an independent Time-Stamping Authority (TSA), providing a time anchor that is independent of the operator's system clock. Note: TSA timestamping is optional and non-blocking; if not configured, time rests on the operator's self-asserted clock. See [control-mapping.md](./control-mapping.md) for the gap analysis.

**Element (3) — Identity of the actor**
*(internal map row: f)(2)(i)(A)(3))*

Every record cryptographically binds an `actor` field and `signer_key_id`; these fields cannot be altered without invalidating the hybrid Ed25519+ML-DSA-65 signature. Deployer obligation: Aevum binds the identity the caller supplies; the deployer is responsible for ensuring that actor attribution is accurate, individually assigned, and not shared across accounts. See [control-mapping.md](./control-mapping.md) for the complete gap analysis.

**Element (4) — Authenticity, reliability, and re-creation**
*(internal map row: f)(2)(i)(A)(4))*

Aevum produces tamper-evident, append-only records with cryptographic audit trails **supporting** the audit-trail alternative under SEC Rule 17a-4(f)(2)(i)(A) — including independent re-creation and verification of records via a standalone verifier. The `aevum-verify` package is open-source and self-contained: any third party — including regulators or opposing counsel — can verify record authenticity using only the public key and the verifier package, without access to the Aevum vendor or the deploying firm's systems.

**Download and transfer — (f)(2)(iv)**
*(internal map row: f)(2)(iv))*

Aevum produces audit pack exports (PROV-O JSON-LD) containing the record and its complete audit trail. The same bundle is consumed by `aevum-verify` for independent verification. Whether the export format constitutes "reasonably usable" within a given examination context is the firm's determination.

---

## Federal Rules of Evidence — Authentication Support

*Internal map rows: FRE 901, 902(13), 902(14) — all tagged `verified (primary source)` in [control-mapping.md](./control-mapping.md).*

> These capabilities support authentication of Aevum-generated records in US federal proceedings. Admissibility is a determination for the court. Aevum provides the cryptographic predicates; counsel lays the evidentiary foundation.

**Records carry independently-verifiable signatures and optional RFC 3161 timestamps.**
The standalone `aevum-verify` package lets any party — including a court-appointed expert — confirm record authenticity and integrity without trusting the vendor.

**Supports authentication under FRE 901.**
*(internal map row: FRE 901)*

Hybrid Ed25519+ML-DSA-65 signatures and Merkle inclusion proofs provide the cryptographic basis through which a proponent can demonstrate that an Aevum record is what it purports to be.

**Supports the self-authentication mechanism of FRE 902(13) and FRE 902(14).**
*(internal map rows: FRE 902(13), FRE 902(14))*

The standalone verifier combined with a qualified-person certification (see [`docs/legal/fre-902-13-certification-template.md`](../legal/fre-902-13-certification-template.md)) provides the instrument for self-authentication under FRE 902(13)/(14). Hash comparison is the digital identification process expressly endorsed in the FRE Advisory Committee note to these rules. Counsel determines whether this satisfies the specific evidentiary context.

---

## What Aevum Does Not Claim

| Claim | Why it is not made |
|---|---|
| "17a-4 compliant" | Compliance is a determination for the firm's counsel based on its specific deployment, policies, and context — not a property of a library |
| "SEC-approved" | The SEC does not approve specific products; the audit-trail alternative is a standard that firms must satisfy in their deployments |
| "Court-admissible" | Admissibility is the court's determination; Aevum provides the cryptographic predicates that support authentication, not the evidentiary ruling |
| "Guarantees compliance" | No technical tool guarantees regulatory compliance; deployers must maintain appropriate policies, procedures, and legal arrangements |
| EU AI Act "compliant" | EU AI Act compliance depends on system classification, deployment context, and application dates that Aevum cannot determine for a deployer; the internal control-map rows for EU Art. 12/18/26 are marked UNVERIFIED and are not present on this page |
| NIST SP 800-53 "compliant" | SP 800-53 controls require organizational implementation programs; Aevum addresses specific AU and SA control mechanisms but the full internal-map rows for AU-8/9/9(3)/10 and SA-8(23) are marked UNVERIFIED and are not present on this page |

---

## Trace to Internal Control Map

Every claim on this page maps to a row in [control-mapping.md](./control-mapping.md):

| Claim (this page) | Internal map row |
|---|---|
| Append-only ledger; modifications captured | 17a-4(f)(2)(i)(A)(1) |
| Date and time of every action; TSA option | 17a-4(f)(2)(i)(A)(2) |
| Actor identity cryptographically bound | 17a-4(f)(2)(i)(A)(3) |
| Authenticity, reliability, re-creation via standalone verifier | 17a-4(f)(2)(i)(A)(4) |
| Audit pack export (record + audit trail) | 17a-4(f)(2)(iv) |
| FRE 901 authentication support | FRE 901 |
| FRE 902(13)/(14) self-authentication support | FRE 902(13), FRE 902(14) |

No claim appears on this page without a corresponding verified internal row.

---

## Technical Basis

Claims on this page are grounded in:

| Specification | Role |
|---|---|
| [`docs/spec/aevum-signing-v1.md`](../spec/aevum-signing-v1.md) | Canonical signing protocol: RFC 8785 JCS canonicalization, hybrid Ed25519+ML-DSA-65 |
| [`docs/spec/aevum-event-v1.json`](../spec/aevum-event-v1.json) | Machine-readable AuditEvent schema |
| [`docs/compliance/control-mapping.md`](./control-mapping.md) | Internal control map with verification status for every row and gap analysis |

---

*Last reviewed: 2026-06-12. Before citing any capability from this page in a customer proposal, RFP response, or regulatory submission, confirm that [control-mapping.md](./control-mapping.md) has not been updated with material gap findings since this date.*
