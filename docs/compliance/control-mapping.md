---
description: "Internal control mapping: SEC Rule 17a-4(f)(2)(i)(A), EU AI Act Arts. 12/18/26, NIST SP 800-53, and FRE 901/902 mapped to Aevum mechanisms, source artifacts, and explicit gaps. Internal reference only — for external capability claims see regulatory-alignment.md."
---

# Aevum Control Mapping — Internal Reference

**Audience:** Compliance, legal, and technical staff conducting internal assessments and audit preparation.

> **Not for external publication as-is.** For defensible external capability claims derived from this map, see [regulatory-alignment.md](./regulatory-alignment.md).

---

## Disclaimer

*Aevum is a tool that helps firms meet recordkeeping obligations; it does not itself constitute compliance, which depends on the firm's policies, procedures, and deployment. Not legal advice.*

---

## Methodology

Each row in this document follows the same discipline:

1. **Requirement (cited)** — exact citation to the primary source (CFR paragraph, regulation article, NIST control, FRE rule)
2. **Verification status** — every citation is tagged `verified (primary source)` or `UNVERIFIED — confirm before external use` (see key below)
3. **Aevum mechanism** — what Aevum does to address the requirement
4. **Artifact(s)** — the specific file, function, or package that implements the mechanism (every artifact named here exists on the main branch)
5. **Gap / hedge** — what Aevum does NOT cover; what the deployer must supply

**Gate for external eligibility:** A claim is external-eligible only if (a) this map traces it to shipped code or the standalone verifier, AND (b) it survives as a *capability* statement, not a compliance determination. "Compliant" is a determination the customer's counsel makes about *their* deployment — never something a library asserts. Every external claim in [regulatory-alignment.md](./regulatory-alignment.md) cites its row in this document; no external claim exists without a trace here.

---

## Verification Status Key

| Tag | Meaning |
|---|---|
| `verified (primary source)` | Citation confirmed against eCFR or primary regulatory text at the time this document was authored |
| `UNVERIFIED — confirm before external use` | Citation not yet confirmed against a primary source in this preparation; treat as provisional; do not rely on sub-citations in external communications until independently verified against the current text |

---

## SEC Rule 17a-4 — Electronic Recordkeeping (17 CFR § 240.17a-4)

### Citation Accuracy Note

> A widely-circulated vendor blog and some secondary commentary cites the audit-trail alternative as "(f)(2)(ii)(A)". **This is incorrect.** The codified audit-trail alternative is **(f)(2)(i)(A)** per 17 CFR § 240.17a-4 as amended by the 2022 amendments (compliance date May 2023; adopting release SEC Release No. 34-96034). Do not repeat the error in any external document.

### 17a-4(f)(2)(i)(A) — The Audit-Trail Alternative

*Spine of this mapping — verified against eCFR Title 17 §240.17a-4 and SEC adopting release 34-96034.*

The audit-trail alternative permits broker-dealers to preserve electronic records without WORM storage, provided the system maintains a complete, time-stamped audit trail that captures the four elements below and permits re-creation of the original record if it is modified or deleted.

| Requirement | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **(f)(2)(i)(A)(1)** All modifications to and deletions of the record or any part thereof | verified (primary source) | Append-only sigchain: modifications are new appended events; Merkle consistency proofs detect any historical rewrite; Barrier 4 (`ImmutableLedgerError`) unconditionally prevents in-place deletion or modification — no delete API exists | `packages/aevum-core/src/aevum/core/audit/sigchain.py` · `packages/aevum-core/src/aevum/core/audit/merkle.py` (`verify_consistency`) · `packages/aevum-core/src/aevum/core/barriers.py` (Barrier 4) | Aevum records agent actions it intercepts through its governed membrane. Out-of-band edits to external systems made without going through Aevum's `ingest()` call are not captured |
| **(f)(2)(i)(A)(2)** The date and time of actions that create, modify, or delete the record | verified (primary source) | Every event carries `system_time` (hybrid logical clock, self-asserted by the operator's process) and optionally an RFC 3161 TSA token obtained over the Signed Tree Head (STH) Merkle root — an independent, third-party time anchor | `packages/aevum-core/src/aevum/core/audit/event.py` (`system_time` field) · `packages/aevum-core/src/aevum/core/tsa.py` · `packages/aevum-core/src/aevum/core/audit/merkle.py` (STH TSA anchoring) | TSA timestamping is non-blocking: if the TSA request fails, the event carries only self-asserted time. Absence of a TSA token is not record invalidity, but the time assertion then rests on the operator's clock alone with no independent anchor |
| **(f)(2)(i)(A)(3)** The identity of the individual creating, modifying, or deleting the record | verified (primary source) | `actor` field and `signer_key_id` are signed fields present in every event; hybrid Ed25519+ML-DSA-65 signatures bind these fields so any tampering invalidates verification | `packages/aevum-core/src/aevum/core/audit/event.py` (`actor`, `signer_key_id`) · `packages/aevum-core/src/aevum/core/signing.py` | Identity is as trustworthy as the caller's `actor` attribution. Aevum binds the identity supplied to it but does not authenticate the underlying human against an identity provider (OIDC, SSO). Deployers must ensure actor attribution is accurate, controlled, and not shared (shared service accounts prevent individual attribution) |
| **(f)(2)(i)(A)(4)** Any other information needed to maintain an audit trail in a way that maintains security, signatures, and data to ensure authenticity and reliability and will permit re-creation of the original record if it is modified or deleted | verified (primary source) | Hybrid Ed25519+ML-DSA-65 signatures; SHA3-256 payload hash; prior-hash Merkle chain from genesis; RFC 6962-style Merkle log with STH; standalone `aevum-verify` package enables offline re-creation and verification by any third party without vendor access | `packages/aevum-verify/src/aevum/verify/_core.py` (`verify_consistency`, `verify_inclusion`, `verify_sth`) · `packages/aevum-core/src/aevum/core/signing.py` · `packages/aevum-core/src/aevum/core/audit/merkle.py` | Re-creation covers Aevum-captured records only. Signature authenticity assumes secure custody of the pinned signing keys; a key compromise means forged events with valid signatures could be produced. Records not routed through Aevum's governed membrane are outside scope |

### 17a-4(f)(2)(iv) — Download and Transfer

| Requirement | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **(f)(2)(iv)** Capacity to readily download, output, and transfer a record and its complete audit trail in both a human-readable format and a reasonably usable electronic format | verified (primary source) | Audit pack export (PROV-O JSON-LD) bundles sigchain entries with provenance metadata in a structured, portable format; the same bundle is consumed by `aevum-verify` for independent verification | `packages/aevum-core/src/aevum/core/audit/audit_pack.py` · `packages/aevum-verify/` | Export format is Aevum's PROV-O JSON-LD dialect. Whether this constitutes "reasonably usable" is the firm's determination, not Aevum's assertion. Aevum does not supply a regulator submission portal or regulated-format converter |

### 17a-4(f)(3)(v) and (f)(3)(vii) — DEO/D3P Undertakings

> **Note on sub-letter verification:** The exact sub-paragraph letters (f)(3)(v) and (f)(3)(vii) for the DEO/D3P undertakings regime are flagged for verification against the current eCFR text before external use. The 2022 amendments introduced D3P requirements but the precise sub-letters should be confirmed against 17 CFR § 240.17a-4 in the eCFR.

| Requirement | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **(f)(3)(v)/(vii)** [exact sub-letters unconfirmed] DEO/D3P undertakings regime: broker-dealers must maintain arrangements for a designated examining organization and designated third party to access records and audit trails | UNVERIFIED — confirm before external use | Aevum is not itself a DEO or D3P. It produces independently verifiable records and audit packs that a D3P arrangement can access and reference | `packages/aevum-core/src/aevum/core/audit/audit_pack.py` · `packages/aevum-verify/` | Aevum does not fulfill the DEO/D3P undertaking obligation. The firm must establish its own D3P arrangement. Aevum produces the records that the D3P arrangement accesses; the logistics of that access are the firm's responsibility |

### 17a-4(j) — Furnish Records on Demand

| Requirement | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **17a-4(j)** Furnish any preserved record and its audit trail in a reasonably usable format to the Commission or other designated examining organization on demand | verified (primary source) | Audit pack export and `aevum-verify` together produce a self-contained, independently verifiable bundle that a regulator can inspect without access to the firm's internal systems or Aevum's infrastructure | `packages/aevum-core/src/aevum/core/audit/audit_pack.py` · `packages/aevum-verify/` | "Reasonably usable" is the regulator's determination. Aevum does not integrate with regulatory submission portals or manage the procedural logistics of responding to examination requests |

---

## EU AI Act — Articles 12, 18, and 26

> **Status: UNVERIFIED — confirm before external use.** Article numbers and application dates below must be verified against the consolidated text of Regulation (EU) 2024/1689 as published in the Official Journal. Application dates were revised by the Digital Omnibus Regulation (under legislative consideration as of the document date); dates below reflect the May 2026 political agreement — December 2, 2027 for certain standalone AI systems; August 2, 2028 for the full obligations — but are **pending Official Journal publication and entry into force**. Verify all dates against the published OJ text before relying on them in any external communication or regulatory submission.

| Requirement | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **Art. 12(1)** Providers of high-risk AI systems must ensure automatic recording of events ("logging") during operation; logs must enable post-hoc identification of the system, responsible persons, the time period of operation, input data used (as hashes), and output | UNVERIFIED — confirm before external use | Automatic, tamper-evident event log: every `ingest`, `query`, `review`, `commit`, and `replay` call appends a signed, chained event recording actor, timestamp, event type, and SHA3-256 payload hash | `packages/aevum-core/src/aevum/core/audit/sigchain.py` · `packages/aevum-core/src/aevum/core/audit/event.py` · `packages/aevum-core/src/aevum/core/audit/audit_pack.py` | Aevum logs actions mediated through its governed membrane. Deployers must retain logs for the period required by applicable sectoral law — Aevum does not enforce retention periods. Deployers must document the logging design and make it available to notified bodies on request |
| **Art. 12(2)** Logs must be kept for the period specified in applicable Union or national law (minimum six months applies in some contexts) | UNVERIFIED — confirm before external use | Append-only sigchain preserves all entries by design; no automatic deletion mechanism exists | `packages/aevum-core/src/aevum/core/audit/sigchain.py` · `packages/aevum-core/src/aevum/core/barriers.py` (Barrier 4) | Retention period enforcement is the deployer's responsibility. Aevum does not purge, archive, or migrate records on a schedule; the deployer must integrate with appropriate long-term storage infrastructure |
| **Art. 18** Documentation: technical documentation for high-risk AI systems must be kept for ten years after the system is placed on the market or put into service | UNVERIFIED — confirm before external use | Audit pack export produces a durable, self-contained, independently verifiable documentation bundle | `packages/aevum-core/src/aevum/core/audit/audit_pack.py` | Aevum does not manage a ten-year archive or enforce retention lifecycles. Deployers must route audit pack exports to appropriate long-term storage and implement retention governance |
| **Art. 26** Deployer obligations: deployers of high-risk AI systems must ensure appropriate logging of system operation and monitor the system with regard to its operation | UNVERIFIED — confirm before external use | All governed operations are automatically logged to the append-only episodic ledger; `replay()` enables post-hoc reconstruction of any past decision for monitoring and review purposes | `packages/aevum-core/src/aevum/core/audit/sigchain.py` · `packages/aevum-core/src/aevum/core/audit/event.py` | Art. 26 obligations rest with the deployer. Aevum provides logging infrastructure; the deployer must implement monitoring workflows, incident response procedures, and the broader Art. 26 compliance program |

---

## NIST SP 800-53 — Security and Privacy Controls

> **Status: UNVERIFIED — confirm before external use.** Control text, control numbers, and enhancement designations below reflect the generally published SP 800-53 Rev. 5 structure but have not been verified line-by-line against the current NIST SP 800-53 publication. Confirm exact control text and applicability against the current NIST publication before citing in any customer-facing or regulatory submission.

| Control | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **AU-8 — Time Stamps** Requires the information system to use internal system clocks to generate time stamps for audit records | UNVERIFIED — confirm before external use | HLC `system_time` in every event; optional RFC 3161 TSA token provides an independent, third-party time anchor distinct from the operator's system clock | `packages/aevum-core/src/aevum/core/audit/event.py` · `packages/aevum-core/src/aevum/core/tsa.py` | TSA is optional and non-blocking. Deployers must configure TSA endpoints for production workloads that require independent time attestation; the default dev-mode NullBackend sends no real TSA requests |
| **AU-9 — Protection of Audit Information** Requires protecting audit information and audit tools from unauthorized access, modification, and deletion | UNVERIFIED — confirm before external use | Barrier 4 (`ImmutableLedgerError`) enforces append-only at the application layer; Ed25519+ML-DSA-65 signatures detect any modification; no deletion API is exposed | `packages/aevum-core/src/aevum/core/barriers.py` (Barrier 4) · `packages/aevum-core/src/aevum/core/audit/sigchain.py` | Aevum does not control OS-level or storage-level access to the underlying SQLite WAL store or Oxigraph/Postgres backends. Storage-layer access controls are the deployer's responsibility |
| **AU-9(3) — Cryptographic Protection** Enhancement: employ cryptographic mechanisms to protect the integrity of audit information and audit tools | UNVERIFIED — confirm before external use | Ed25519+ML-DSA-65 hybrid signatures over every event; SHA3-256 prior-hash Merkle chaining; RFC 6962-style Merkle tree with signed STH provides log-level integrity | `packages/aevum-core/src/aevum/core/signing.py` · `packages/aevum-core/src/aevum/core/audit/merkle.py` · `packages/aevum-core/src/aevum/core/audit/sigchain.py` | Cryptographic protection depends on secure key custody. Deployers requiring private keys outside the aevum-core process should use `VaultTransitSigner` (external signing) — it implements the same `DualSigner` interface but the private key never enters the Aevum process |
| **AU-10 — Non-Repudiation** Provides non-repudiation of actions so that individuals cannot falsely deny having performed a given action | UNVERIFIED — confirm before external use | Ed25519+ML-DSA-65 signatures bind `actor` and `signer_key_id` into every event; these fields cannot be altered without invalidating the signature | `packages/aevum-core/src/aevum/core/signing.py` · `packages/aevum-core/src/aevum/core/audit/event.py` | Non-repudiation is as strong as actor attribution. Shared service accounts or unauthenticated actor values prevent non-repudiation of specific individuals. Deployers must enforce individual actor attribution at the call site |
| **SA-8(23) — Design Principle: Provenance** Apply the security engineering principle of provenance: maintain the origin and chain of custody of data and system components throughout the lifecycle | UNVERIFIED — confirm before external use | Barrier 5 requires `source_id` for every ingested record; `urn:aevum:provenance` named graph records chain of custody for all governed data; `ingest()` signature makes `source_id` a required parameter | `packages/aevum-core/src/aevum/core/barriers.py` (Barrier 5) · `packages/aevum-core/src/aevum/core/audit/audit_pack.py` | Aevum tracks provenance for data ingested through its governed membrane. Lineage from upstream ETL pipelines or external systems that bypass the membrane is the deployer's responsibility |

---

## Federal Rules of Evidence — Authentication Support

> These rows address how Aevum-generated records can support authentication in US federal proceedings. The frame throughout is "supports authentication under" — admissibility is a determination for the court, not an assertion a library makes. See also [`docs/legal/fre-902-13-certification-template.md`](../legal/fre-902-13-certification-template.md).

| Requirement | Verification status | Aevum mechanism | Artifact(s) | Gap / hedge |
|---|---|---|---|---|
| **FRE 901** Authentication — evidence must be what its proponent claims it is; proponent must produce evidence sufficient to support a finding that the item is what the proponent claims | verified (primary source) — FRE text is stable federal rule | Hybrid signatures and Merkle inclusion proofs enable any party to verify that an Aevum record is genuine and unmodified; `aevum-verify` is the verification instrument | `packages/aevum-verify/src/aevum/verify/_core.py` · `packages/aevum-core/src/aevum/core/signing.py` | FRE 901 authentication requires a fact-finder determination, not a software output. Aevum provides the cryptographic predicate; counsel must lay the appropriate evidentiary foundation |
| **FRE 902(13)** Self-authentication: certified records generated by an electronic process or system — a party may authenticate a record by providing a written certification from a qualified person attesting: (A) the record was generated by an electronic process or system that produces an accurate result, and (B) describing the process and the system | verified (primary source) — FRE text is stable federal rule | The standalone `aevum-verify` package combined with a qualified-person certification is the 902(13) instrument. The certification template at `docs/legal/fre-902-13-certification-template.md` provides the attesting structure | `packages/aevum-verify/src/aevum/verify/_core.py` · `docs/legal/fre-902-13-certification-template.md` | Self-authentication under 902(13) requires a signed certification from a qualified person at the deploying organization — not merely running the verifier. The certification template is a starting point; counsel must determine whether it satisfies the specific evidentiary context and jurisdiction |
| **FRE 902(14)** Self-authentication: certified copies of records generated by an electronic process or system — authentication by a written certification from a qualified person attesting that: (A) the record was regularly conducted in the regular course of activity; and (B) the digital identification process is reliable | verified (primary source) — FRE text is stable federal rule | `aevum-verify` combined with the certification template provides the attestation structure for 902(14); hash comparison is the digital identification process explicitly noted in the FRE Advisory Committee note to 902(13)/(14) | `packages/aevum-verify/src/aevum/verify/_core.py` · `docs/legal/fre-902-13-certification-template.md` | Admissibility under 902(14) is the court's determination. Aevum provides the verifiable record and the verification instrument; the qualified-person certification, its adequacy for the specific proceeding, and any hearsay objections are outside Aevum's scope |

---

## Technical Basis

The mechanisms in this control map are implemented and documented in:

| Artifact | Role |
|---|---|
| [`docs/spec/aevum-signing-v1.md`](../spec/aevum-signing-v1.md) | Canonical signing specification: RFC 8785 JCS canonicalization, domain separators, hybrid Ed25519+ML-DSA-65 protocol |
| [`docs/spec/aevum-event-v1.json`](../spec/aevum-event-v1.json) | Machine-readable JSON Schema for the AuditEvent (the episodic ledger entry format) |
| [`docs/spec/aevum-event-v1.md`](../spec/aevum-event-v1.md) | AuditEvent field reference: chain-linkage semantics, signing fields, nullable Phase 1 fields |
| `packages/aevum-core/src/aevum/core/audit/sigchain.py` | Sigchain implementation: append-only, Ed25519-chained, Barrier-4-protected |
| `packages/aevum-core/src/aevum/core/audit/merkle.py` | RFC 6962-style Merkle tree, STH, inclusion and consistency proofs |
| `packages/aevum-core/src/aevum/core/audit/event.py` | AuditEvent dataclass: 19 core fields including `system_time`, `actor`, `signer_key_id` |
| `packages/aevum-core/src/aevum/core/tsa.py` | RFC 3161 TSA client; optional, non-blocking, rate-limit-aware |
| `packages/aevum-core/src/aevum/core/signing.py` | DualSigner: Ed25519+ML-DSA-65 hybrid signing engine |
| `packages/aevum-core/src/aevum/core/audit/audit_pack.py` | PROV-O JSON-LD audit pack export |
| `packages/aevum-core/src/aevum/core/barriers.py` | Five unconditional barriers; Barrier 4 enforces append-only; Barrier 5 enforces provenance |
| `packages/aevum-verify/src/aevum/verify/_core.py` | Standalone verifier: `verify_consistency`, `verify_inclusion`, `verify_sth`, `verify_sth_tsa_full` |
| [`docs/legal/fre-902-13-certification-template.md`](../legal/fre-902-13-certification-template.md) | FRE 902(13) certification template for qualified persons |

---

## Flags for Follow-Up

The following items are explicitly flagged `UNVERIFIED` and must be confirmed against primary sources before any external publication or regulatory submission:

1. **17a-4(f)(3)(v)/(vii) sub-letters** — confirm exact sub-paragraph letters for DEO/D3P undertakings against current eCFR Title 17 §240.17a-4
2. **EU AI Act article numbers and dates** — confirm Art. 12, 18, 26 text against the consolidated Regulation (EU) 2024/1689 text; confirm application dates against the Official Journal once the Digital Omnibus Regulation is published
3. **NIST SP 800-53 control text** — confirm AU-8, AU-9, AU-9(3), AU-10, SA-8(23) text against the current NIST SP 800-53 Rev. 5 publication

*Last reviewed: 2026-06-12. Refresh verification status tags before any external publication or regulatory submission.*
