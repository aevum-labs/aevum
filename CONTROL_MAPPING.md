# Aevum Control Mapping

This document maps Aevum's technical controls to regulatory frameworks
and security standards.

Read this document alongside THREAT_MODEL.md.

---

## How to Read This Document

**Supported:** Aevum provides a technical control directly relevant to
this requirement. This does not mean your application is compliant —
compliance depends on your full deployment, configuration, and
surrounding controls.

**Partial:** Aevum addresses some aspects of this requirement. The
specific gap is described.

**Tension:** Aevum's design creates a structural consideration for this
requirement that you must address in your deployment.

**Not addressed:** This requirement is outside Aevum's scope.

---

## Version

Controls mapped against: aevum-core v0.3.0
Last reviewed: May 2026

Regulatory requirements change. Verify against the current text of each
regulation before relying on this mapping for compliance decisions.
This document is not legal advice.

---

## US Regulatory Landscape

### HIPAA (45 CFR Parts 160 and 164)

| Requirement | Coverage | Notes |
|---|---|---|
| §164.312(b) Audit controls — record and examine activity | **Supported** | Sigchain records every operation with actor, timestamp, and payload hash |
| §164.312(a)(2)(i) Unique user identification | **Partial** | Aevum records `actor` per operation; identity issuance is your application's responsibility |
| §164.312(c)(2) Mechanism to authenticate electronic PHI | **Partial** | Ed25519 signature verifies record authenticity; field-level PHI integrity is your responsibility |
| §164.312(e)(2)(ii) Encryption in transit | **Not addressed** | TLS is your infrastructure responsibility |
| Minimum necessary (§164.502(b)) | **Partial** | Classification ceiling (Barrier 2) enforces access tiers; minimum-necessary analysis is your responsibility |
| Business Associate Agreements | **Not addressed** | Each MCP or tool call processing PHI may create BAA obligations; Aevum does not manage BAAs |
| FIPS 140-3 validated cryptography | **Not addressed** | Default in-process Ed25519 is not FIPS 140-3 validated; use HSM/KMS for FIPS compliance |
| Breach notification (§164.400–414) | **Partial** | Sigchain provides breach evidence artifacts; notification workflow is your responsibility |

**Summary:** Aevum is designed to support HIPAA §164.312(b) audit-control
implementations. It does not satisfy HIPAA as a whole. Full HIPAA
compliance for AI systems requires BAA management, FIPS 140-3 validated
cryptography, minimum-necessary policies, and a Security Risk Analysis.

---

### FTC Act Section 5

| Consideration | Notes |
|---|---|
| Substantiation of product capability claims | Aevum's documentation uses "designed to support" rather than "satisfies" or "compliant with." If you make marketing claims about your product's compliance or security posture based on Aevum's controls, those claims must be independently substantiated. |

---

### CCPA / CPRA + CPPA ADMT Regulations (effective Jan 1, 2026)

| Requirement | Coverage | Notes |
|---|---|---|
| Opt-out of automated decision-making | **Partial** | Consent ledger records grants and revocations; opt-out propagation to downstream systems is your responsibility |
| Pre-use notice to consumers | **Not addressed** | Your responsibility |
| Right to access personal information | **Partial** | Sigchain provides an audit record; a consumer-facing access workflow is your responsibility |
| Risk assessments (8 enumerated elements, due Dec 31, 2027) | **Not addressed** | Aevum can produce evidence artifacts but does not perform assessments |
| Cybersecurity audits | **Not addressed** | Aevum can support audit evidence; the audit itself requires a qualified third party |

---

### NIST AI RMF 1.0 + GenAI Profile (NIST AI 600-1)

| Function / Category | Coverage | Notes |
|---|---|---|
| GV-1.4 — Logging and monitoring of AI system behavior | **Supported** | Sigchain + episodic ledger |
| GV-1.5 — Audit and accountability mechanisms | **Supported** | Sigchain + consent ledger |
| MS-2.7 — Model integrity monitoring | **Partial** | Sigchain records every ingest/query/commit |
| MG-3.2 — Incident response data | **Supported** | Sigchain provides forensic artifacts |
| MG-3.1 — Human oversight mechanisms | **Partial** | review() gate + veto-as-default; integration is your responsibility |
| MAP-1 — Risk identification and contextualization | **Not addressed** | Requires organizational risk process |
| MEAS-2.6 — Fairness and bias measurement | **Not addressed** | |
| MEAS-2.11 — Bias testing | **Not addressed** | |
| MAP-5.1 — Adversarial testing / red-teaming | **Not addressed** | |
| MEAS-2.10 — Training data provenance | **Not addressed** | |

**Summary:** Aevum maps to the logging, monitoring, and accountability
functions of NIST AI RMF. It does not address risk identification, bias
measurement, or adversarial testing. Colorado SB 26-189 and Texas TRAIGA
both reference NIST AI RMF safe harbor — Aevum supports the evidence
generation portion of that argument but does not by itself constitute
substantial compliance.

---

### NY Local Law 144 (AEDT)

| Requirement | Coverage | Notes |
|---|---|---|
| Annual independent bias audit | **Not addressed** | Must be performed by a qualified third party |
| Public posting of audit summary | **Not addressed** | Your responsibility |
| Candidate notice (≥10 business days) | **Not addressed** | Your responsibility |
| Audit evidence retention | **Supported** | Sigchain provides tamper-evident audit artifacts |

---

### Illinois BIPA

| Requirement | Coverage | Notes |
|---|---|---|
| Written consent before collecting biometric data | **Partial** | Consent ledger can record BIPA-required consent; the consent-collection workflow is your responsibility |
| Retention and destruction policy | **Partial** | Sigchain records ingestion; destruction policy enforcement is your responsibility |

---

## Global Regulatory Coverage

### EU AI Act (Regulation 2024/1689)

Applies to high-risk AI systems under Annex III.
Obligations applicable 2 December 2027 (Annex III) per Digital Omnibus.

| Article | Requirement | Coverage | Notes |
|---|---|---|---|
| Art. 12 | Automatic recording of events | **Supported** | Sigchain produces automatically generated, tamper-evident logs |
| Art. 19 | Log retention (≥6 months per Art. 26(6)) | **Supported** | Retention period is your infrastructure configuration |
| Art. 13 | Transparency to deployers | **Partial** | Sigchain supports deployer monitoring; end-user transparency requires additional controls |
| Art. 14 | Human oversight | **Partial** | review() gate + veto-as-default; full integration is your responsibility |
| Art. 15 | Accuracy, robustness, cybersecurity | **Partial** | Sigchain supports cybersecurity audit trail; accuracy and robustness testing is separate |
| Art. 9 | Risk management system | **Not addressed** | Requires organizational process |
| Art. 10 | Data governance | **Not addressed** | Training data lineage, bias examination, data quality |
| Art. 11 | Technical documentation (Annex IV) | **Not addressed** | Must cover the full AI system |
| Art. 17 | Quality management system | **Not addressed** | Organizational process |
| Art. 18 | Technical documentation retention (10 years) | **Not addressed** | Infrastructure configuration |
| Art. 72 | Post-market monitoring | **Partial** | Sigchain provides incident forensics; monitoring program is your responsibility |

**Defensible claim:** Aevum is designed to support EU AI Act Article 12
record-keeping requirements for high-risk AI systems. Full compliance
with the EU AI Act for high-risk systems requires additional controls
outside Aevum's scope, covering Articles 9–11, 13–15, 17–18, and 72.

**Penalty reference (Art. 99):** Up to €15M or 3% of global annual
turnover for Article 12 violations; up to €35M or 7% for prohibited
practices.

---

### GDPR (Regulation 2016/679)

| Article | Requirement | Coverage | Notes |
|---|---|---|---|
| Art. 17 — Right to erasure | **Tension** | Aevum's append-only ledger retains signed audit records. Consent revocation (revoke_consent_grant) makes data unreachable but does not delete ledger entries. Assess with qualified counsel for your jurisdiction. |
| Art. 20 — Data portability | **Partial** | Structured AuditEvent format supports export; consumer-facing portability workflow is your responsibility |
| Art. 22 — Solely automated decision-making | **Not addressed** | Requires human intervention mechanisms and explanation of decisions; review() gate supports intervention but does not generate explanations |
| Art. 25 — Data protection by design | **Supported** | Classification ceiling + consent-as-precondition aligns with privacy-by-design |
| Art. 32 — Security of processing | **Partial** | Ed25519 signing + SHA3-256 chaining; encryption at rest is your infrastructure responsibility |
| Art. 35 — Data Protection Impact Assessment | **Not addressed** | Aevum can produce evidence artifacts; the DPIA is your responsibility |

---

### Brazil LGPD

| Article | Requirement | Coverage | Notes |
|---|---|---|---|
| Art. 20 — Review of solely-automated decisions | **Partial** | replay() retrieves the signed record; generating a human-readable explanation is your responsibility |
| Art. 46 — Security measures | **Supported** | Sigchain supports audit and accountability |

---

### India DPDP Act 2023 + Rules (2025, full compliance by May 13, 2027)

| Requirement | Coverage | Notes |
|---|---|---|
| Rule 6 — Audit logs with 1-year minimum retention | **Supported** | Sigchain designed to satisfy Rule 6 audit-log requirements |
| Verifiable parental consent (under-18) | **Partial** | Consent ledger records consent; age verification is your application's responsibility |
| 72-hour breach notification | **Partial** | Sigchain provides breach evidence; notification workflow is your responsibility |

---

### Singapore Model AI Governance Framework for GenAI (May 2024)

| Dimension | Coverage | Notes |
|---|---|---|
| Accountability | **Supported** | Sigchain provides accountability records |
| Incident reporting | **Supported** | Sigchain provides forensic artifacts |
| Content provenance | **Not addressed** | |
| Testing and assurance | **Not addressed** | |
| Safety and alignment | **Partial** | Five unconditional barriers address a subset of safety concerns |

---

## AI Security Standards

### OWASP Top 10 for Agentic AI (ASI01–ASI10, December 2025)

| Risk | Coverage | Notes |
|---|---|---|
| ASI01 — Agent Goal Hijack | **Partial** | Barriers check provenance and consent; no input classification |
| ASI02 — Tool/Resource Misuse | **Partial** | Consent + classification ceiling limits data access scope |
| ASI03 — Identity and Privilege Abuse | **Partial** | Records actor per operation; does not issue or verify identity |
| ASI04 — Supply Chain Attacks | **Not addressed** | |
| ASI05 — Unexpected Code Execution | **Not addressed** | |
| ASI06 — Memory and Context Poisoning | **Partial** | Consent-gated writes reduce injection surface; detectable via sigchain forensics after the fact |
| ASI07 — Insecure Inter-Agent Communication | **Not addressed** | No mTLS at library layer |
| ASI08 — Cascading Agent Failures | **Not addressed** | |
| ASI09 — Human-Agent Trust Exploitation | **Not addressed** | |
| ASI10 — Rogue Agents | **Partial** | Sigchain records rogue actions; does not prevent them |

**Summary:** Aevum directly addresses 2 of 10 OWASP Agentic risks and
partially addresses 3 more. For comprehensive OWASP Agentic Top 10
coverage, complement Aevum with network security controls (mTLS,
SPIFFE/SVID), input validation, and supply chain integrity tools.

---

### ISO/IEC 42001:2023 (AI Management Systems)

| Control | Coverage | Notes |
|---|---|---|
| A.6.2.3 — Logging and monitoring | **Supported** | Sigchain |
| A.6.2.4 — Incident management | **Partial** | Sigchain provides forensics; incident management process is organizational |
| A.8.4 — AI system lifecycle | **Partial** | Version-stamped controls in this document support lifecycle evidence |
| Risk management (Clause 6) | **Not addressed** | Organizational management system |
| Internal audit (Clause 9.2) | **Not addressed** | Organizational |
| Management review (Clause 9.3) | **Not addressed** | Organizational |

**Note:** ISO/IEC 42001 certification is performed against an
organizational management system, not against a library. Aevum can
contribute evidence artifacts to a certification process.

---

### SOC 2 Type II

| Trust Service Criteria | Coverage | Notes |
|---|---|---|
| CC7.2 — System monitoring | **Supported** | Sigchain provides operation-level monitoring records |
| CC7.3 — Incident detection | **Supported** | Sigchain provides forensic artifacts for incident investigation |
| CC6.1 — Logical access controls | **Partial** | Consent ledger provides access-control evidence; infrastructure-layer controls are separate |
| A1.2 — Availability and performance | **Not addressed** | |

---

## What Aevum Does Not Address

The following requirements are outside Aevum's scope:

- LLM bias testing and fairness measurement
- Training data provenance and quality controls
- Adversarial testing and red-teaming
- Business Associate Agreement management (HIPAA)
- FIPS 140-3 validated cryptography in default configuration
- Network-level transport security (TLS, mTLS, SPIFFE/SVID)
- Identity issuance and token validation
- Consumer-facing notice and disclosure workflows
- Risk assessments and Data Protection Impact Assessments
- Explanations of automated decisions (GDPR Art. 22, CCPA ADMT,
  LGPD Art. 20, Brazil LGPD)
- Post-quantum cryptography (Ed25519 is not quantum-resistant;
  PQ migration is on the roadmap)
- Data breach notification workflows
- Organizational quality management systems (ISO 42001 Clauses 4–10)
- External log anchoring via RFC 3161 timestamps or OpenTimestamps
  (planned, not yet shipped)

---

## Disclaimer

This document describes Aevum's technical controls and their
relationship to regulatory requirements as of the review date. It is
not legal advice. Regulatory requirements change, and regulatory
interpretation varies by jurisdiction, context, and auditor.

"Supported" means Aevum provides a relevant technical control. It does
not mean your application satisfies that requirement. Compliance depends
on your full deployment, configuration, organizational processes, and
surrounding controls.

Consult qualified legal counsel before making compliance decisions based
on this document.
