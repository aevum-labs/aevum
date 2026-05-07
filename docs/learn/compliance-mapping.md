# Aevum Compliance Mapping

*Last updated: 2026-05-06. Standards with active rulemaking are marked (LIVE).
This document does not constitute legal advice. Obtain qualified legal and
compliance review before making regulatory assertions based on this content.*

## Coverage Key

| Symbol | Meaning |
|--------|---------|
| ✅ | Aevum satisfies this requirement as deployed |
| ⚠️ | Aevum satisfies with caveats (see Notes column) |
| 🔧 | Requires specific deployment configuration |
| ❌ | Out of scope — deployer responsibility |

---

## AI-Specific Regulation and Standards

| Standard | Provision | Aevum Primitive | Coverage | Notes |
|----------|-----------|-----------------|----------|-------|
| EU AI Act (Reg. 2024/1689) | Art. 12(1) Automatic recording over system lifetime | Barrier 4 + sigchain + session.start | ✅ | Deadline 2 Aug 2026 (Digital Omnibus delay unresolved as of May 2026) |
| EU AI Act | Art. 12(2)(a)–(c) Recording purposes | AuditEvent.payload + episode_id | ✅ | |
| EU AI Act | Art. 12(3) Biometric-specific fields | AuditEvent.payload (deployer-extended) | ⚠️ | Deployer must populate biometric fields |
| EU AI Act | Art. 19(1) Provider log retention ≥6 months | Append-only ledger | 🔧 | Retention period is deployer config |
| EU AI Act | Art. 26(6) Deployer log retention ≥6 months | Append-only ledger | 🔧 | Retention period is deployer config |
| EU AI Act | Art. 18 Technical documentation 10 years | Append-only ledger | 🔧 | Conflicts with GDPR storage limitation for PII |
| prEN ISO/IEC 24970 (DIS) | AI system logging information model | AuditEvent schema | ⚠️ | Standard not yet published; alignment to draft |
| ISO/IEC 42001:2023 | A.6.2.8 Event log recording by lifecycle phase | Sigchain (all phases) | ✅ | Deployer must document which phases are enabled |
| ISO/IEC 42001:2023 | A.6.2.6 AI system monitoring | review() + replay() | ⚠️ | Monitoring workflow is deployer-owned |
| ISO/IEC 23894:2023 | Clause 6.4 Risk treatment documentation | REMEMBER + replay() | ⚠️ | Risk methodology is deployer-owned |
| IEEE 7001-2021 | Level 4–5 transparency (certification/investigators) | Sigchain + replay() | ✅ | |
| NIST AI RMF 1.0 | GOVERN 1.1/4.3 Accountability documentation | Cedar/OPA policy bundles | ⚠️ | Governance docs are deployer-owned |
| NIST AI RMF 1.0 | MEASURE 2.7/2.8 Security/privacy risk logging | Sigchain + AuditEvent | ✅ | |
| NIST AI RMF 1.0 | MANAGE 4.1 Post-deployment monitoring | review() + replay() | ✅ | |
| NIST AI 600-1 (GenAI Profile) | GV-1.1-002 GenAI incident records | AuditEvent + sigchain | ✅ | |
| Colorado SB 24-205 | Impact assessment documentation retention (5 yr) | REMEMBER + payload | 🔧 | Effective 30 Jun 2026; assessment workflow external |
| OECD AI Principles 2024 | Principle 1.4 Traceability | Provenance barrier + sigchain | ✅ | Voluntary |
| G7 Hiroshima AI Code (2023) | Traceability and audit | Sigchain | ✅ | Voluntary |

---

## Healthcare

| Standard | Provision | Aevum Primitive | Coverage | Notes |
|----------|-----------|-----------------|----------|-------|
| HIPAA Security Rule §164.312(b) | Audit controls — record/examine ePHI activity | Sigchain | ✅ | |
| HIPAA 2024 NPRM (LIVE) | Proposed: tamper-evident audit logs | Sigchain (hash-chain) | ✅ | Final rule not yet published (May 2026) |
| HIPAA 2024 NPRM | Proposed: encryption at rest | AES-256 at storage layer | 🔧 | Deployer configures storage encryption |
| HIPAA §164.316(b)(2) | Documentation retention 6 years | Append-only ledger | 🔧 | Retention config |
| FDA 21 CFR §11.10(e) | Independently record, time-stamped | Sigchain + external signer | 🔧 | InProcessSigner: partial (tamper-detectable not tamper-prevented); VaultTransitSigner or PKCS11Signer via aevum-sdk: full |
| FDA 21 CFR §11.10(c) | Protection of records from tampering | Barrier 4 (Audit Immutability) | ✅ | |
| FDA 21 CFR Part 820 / QMSR | §820.180 Record retention 2 yr post-life | Append-only ledger | 🔧 | Retention config; eQMS integration external |
| FDA PCCP Final (Dec 2024) | Modification protocol logging | Provenance barrier + commit() | ✅ | |
| ONC §170.315(d)(2) | Auditable events + tamper-resistance (ASTM E2147) | Sigchain + AuditEvent | ✅ | ASTM E2147 field mapping in policy bundle |
| ONC §170.315(d)(3) | Audit log encryption | Storage-layer encryption | 🔧 | Deployer config |
| HITRUST CSF v11 09.ab | Monitoring system use, tamper-resistance | Sigchain | ✅ | |

---

## Financial Sector

| Standard | Provision | Aevum Primitive | Coverage | Notes |
|----------|-----------|-----------------|----------|-------|
| SOX §302/§404 + PCAOB AS 2201 | IT general controls, record integrity | Sigchain | ⚠️ | 7-year retention (AS 1215); financial reporting linkage external |
| SEC Cyber Rule (Rule S7-09-22) | 8-K 1.05 material incident disclosure | AuditEvent + sigchain | ⚠️ | 4-business-day notification workflow external |
| PCI DSS v4.0 Req 10.2.1 | Event types: access, admin, changes | AuditEvent.event_type | ✅ | |
| PCI DSS v4.0 Req 10.2.2 | Per-event content: user, time, type, outcome | AuditEvent fields | ✅ | |
| PCI DSS v4.0 Req 10.3.4 | FIM / tamper-detection on logs | Hash chain (Barrier 4) | ✅ | |
| PCI DSS v4.0 Req 10.4.1.1 | Automated log review | — | ❌ | SIEM integration; out of kernel scope |
| PCI DSS v4.0 Req 10.5.1 | 12-month retention; 3 months immediate | Append-only ledger | 🔧 | Retention config; index for immediate access |
| PCI DSS v4.0 Req 10.6 | NTP clock synchronisation | HLC + NTP (deployment) | 🔧 | NTP config is deployer responsibility |
| NYDFS Part 500 §500.6(a)(1) | Cybersecurity audit trail 3-yr retention | Append-only ledger | 🔧 | Retention config |
| NYDFS Part 500 §500.6(a)(2) | Financial reconstruction records 5-yr | Append-only ledger | 🔧 | Retention config; financial linkage external |
| NYDFS Part 500 §500.14 | Monitoring for unauthorized access | AuditEvent stream | ⚠️ | SIEM for alerting; Aevum provides substrate |
| NYDFS Part 500 §500.17(b) | CEO+CISO dual certification | — | ❌ | Governance workflow external |
| DORA (Reg. 2022/2554) Art. 17 | ICT-incident logging | AuditEvent | ✅ | |
| DORA Art. 19/20 | 4hr initial / 72hr intermediate / 1mo final report | AuditEvent substrate | ⚠️ | Report templates and timers external |
| DORA Art. 25 | TLPT logging | AuditEvent | ⚠️ | TLPT workflow external |
| MiFID II Art. 25 + RTS 6 | Algorithmic trading audit trail | Sigchain | ✅ | |
| MiFID II RTS 6 Art. 4 | Real-time alerts ≤5 seconds | — | ❌ | SIEM/alerting; out of kernel scope |
| MiFID II RTS 25 | UTC-traceable timestamps | HLC + NTP/PTP config | 🔧 | HLC ≠ UTC traceability; requires NTP/PTP deployment |
| FINRA 4511 / SEA 17a-4 | 6-year retention, WORM or audit-trail alternative | Append-only + 17a-4 audit-trail alternative | 🔧 | D3P attestation required; retention config |
| FINRA CAT Rule 613 | Reportable-event audit trail | AuditEvent substrate | ⚠️ | CAT-specific field mapping external |
| GLBA Safeguards Rule §314.4(c)(8) | Monitoring for unauthorized access | AuditEvent stream | ⚠️ | SIEM for alerting |
| UK FCA SYSC 9 | Record retention 5 years | Append-only ledger | 🔧 | Retention config |

---

## Privacy and Data Protection

| Standard | Provision | Aevum Primitive | Coverage | Notes |
|----------|-----------|-----------------|----------|-------|
| GDPR Art. 7 | Consent freely given, specific, withdrawable | OR-Set CRDT consent | ✅ | |
| GDPR Art. 17 | Right to erasure | Tombstone + payload deletion | ⚠️ | Chain retains hash; payload must be deleted externally |
| GDPR Art. 22 | Automated decision-making documentation | AuditEvent + replay() | ✅ | |
| GDPR Art. 30 | Record of processing activities (ROPA) | AuditEvent operational records | ⚠️ | ROPA document generation is deployer/template |
| GDPR Art. 5(1)(e) | Storage limitation (storage minimisation) | — | ❌ | Conflicts with longer retention requirements; deployer resolves |
| EDPB Opinion 28/2024 | AI training/deployment processing records | AuditEvent substrate | ⚠️ | Opinion interpretation is legal counsel responsibility |
| CCPA/CPRA ADMT regs (eff. 1 Jan 2026) | Risk assessment retention 5 years | REMEMBER + payload | 🔧 | Assessment workflow external |
| CCPA/CPRA | Cybersecurity audit (annual) | Sigchain provides evidence | ⚠️ | Audit itself is external process |
| Colorado SB 24-205 (eff. 30 Jun 2026) | Deployer risk management logging | Sigchain | ✅ | Impact assessment workflow external |
| PIPEDA | General accountability, openness | Sigchain + consent model | ✅ | AIDA dead (Jan 2025); Quebec Law 25 is Canadian baseline |
| Quebec Law 25 | ADM notice and impact assessment | AuditEvent + payload | ⚠️ | Workflow external |
| UK ICO AI Auditing Framework | Fairness/accuracy/security monitoring logs | Sigchain | ✅ | Non-binding guidance |
| Singapore MAS FEAT | Model performance logs, audit trails | Sigchain | ✅ | Voluntary framework |
| APRA CPS 234 | ¶22 Mechanisms to detect security incidents | AuditEvent stream | ⚠️ | Detection/alerting is SIEM layer |
| Australia Privacy Act 2024 | ADM transparency from Dec 2026 | AuditEvent + payload | 🔧 | Workflow external |

---

## Security Standards and Frameworks

| Standard | Provision | Aevum Primitive | Coverage | Notes |
|----------|-----------|-----------------|----------|-------|
| NIST SP 800-53 Rev 5 AU-2 | Event logging — defined event types | Configurable AuditEvent types | ✅ | |
| NIST SP 800-53 AU-3 | Content of audit records (minimum fields) | 18-field AuditEvent schema | ✅ | |
| NIST SP 800-53 AU-8 | Time stamps | HLC + NTP deployment | 🔧 | NTP/PTP is deployer config |
| NIST SP 800-53 AU-9 | Protection of audit information | Barrier 4 (Audit Immutability) | ✅ | |
| NIST SP 800-53 AU-9(2) | Physical storage separation (Mod+) | Separate signer host | 🔧 | Deployment topology |
| NIST SP 800-53 AU-9(3) | Cryptographic protection (High) | Sigchain (Ed25519+SHA3-256) | ✅ | |
| NIST SP 800-53 AU-10 | Non-repudiation (High) | Ed25519 signatures | ✅ | |
| NIST SP 800-53 AU-12 | Audit record generation | Sigchain (all five functions) | ✅ | |
| NIST SP 800-53 AU-12(1) | System-wide time-correlated trail (Mod+) | Sigchain + HLC | ✅ | |
| NIST SP 800-53 AU-14 | Session audit (capture screen/keystrokes) | — | ❌ | Host-OS/endpoint; out of kernel scope |
| NIST SP 800-53 AU-15 | Alternate audit logging | Pluggable store backends | 🔧 | Second store as failover |
| NIST SP 800-53 AU-16 | Cross-organizational logging | PROV-O + VC-DM (Part 2) | 🔧 | Part 2 capability |
| NIST SP 800-53 SI-12 | Information retention | REMEMBER + retention policy | 🔧 | Policy configuration |
| NIST SP 800-53 SI-19 | De-identification | — | ❌ | Out of kernel scope |
| NIST SP 800-53 IR-5 | Incident monitoring | replay() + AuditEvent stream | ✅ | |
| FedRAMP Moderate AU family | AU-2/3/8/9/10/11/12 | As above | ✅ | See NIST rows |
| FedRAMP High AU additions | AU-6(1/3/5), AU-7(1), AU-12(1) | Substrate provided | ⚠️ | SIEM correlation is external |
| NIST SP 800-92 Rev 1 | Log integrity, retention, centralisation | Sigchain | ✅ | |
| ISO/IEC 27001:2022 A.8.15 | Logging (10 event categories) | AuditEvent | ✅ | |
| ISO/IEC 27001:2022 A.8.16 | Monitoring activities | AuditEvent stream | ⚠️ | Active monitoring is SIEM layer |
| ISO/IEC 27001:2022 A.8.17 | Clock synchronisation | HLC + NTP deployment | 🔧 | NTP config |
| SOC 2 CC4.1 | Ongoing monitoring of controls | REPLAY supports evidence | ✅ | |
| SOC 2 CC7.1/7.2 | Anomaly detection | AuditEvent stream | ⚠️ | Detection logic external |
| SOC 2 CC7.3/7.4 | Incident communication/response | AuditEvent substrate | ⚠️ | Workflow external |
| WebhookRegistry dead-letter | Delivery failure visibility | barrier.webhook_failed AuditEvent | ✅ | Ensures review event delivery failures are auditable; supports SOC 2 CC7.4, PCI DSS 10.2.1 |
| CIS Controls v8.1 #8 (all 12 safeguards) | Audit log management | Sigchain + config | ✅ | 90-day minimum retention (much shorter than financial sector) |
| HITRUST CSF v11 09.ab | Monitoring system use | Sigchain | ✅ | |
| OWASP ASI Top 10 ASI05 | Memory/state manipulation | Sigchain + replay() | ✅ | |
| OWASP ASI Top 10 ASI07 | Sensitive data disclosure | Classification ceiling (Barrier 2) | ✅ | |
| OWASP ASI Top 10 ASI10 | Insufficient observability | Five functions + sigchain | ✅ | |
| OWASP ASI Top 10 ASI03 | Identity/privilege abuse | Consent model + aevum-spiffe | 🔧 | SPIFFE agent identity requires SPIRE deployment; see aevum-spiffe package |
| OWASP ASI Top 10 ASI08 | Cascading failure | — | ❌ | SRE/circuit-breaker; out of scope |

---

## Technical Standards

| Standard | Provision | Aevum Primitive | Coverage | Notes |
|----------|-----------|-----------------|----------|-------|
| FIPS 186-5 | Ed25519 algorithm approval | InProcessSigner (Ed25519) | ✅ | Approved Feb 2023 |
| FIPS 180-4 / FIPS 202 | SHA3-256 algorithm approval | Hash chain | ✅ | |
| FIPS 140-3 (module) | Validated cryptographic module | ECDSA P-256/P-384 fallback | 🔧 | Ed25519 not in all validated modules; pluggable signer required |
| RFC 8785 (JCS) | JSON canonicalization for signing | Signing canonical form | ✅ | |
| RFC 3161 (TSA) | Trusted timestamping | TSA hook (Part 2) | 🔧 | Part 2 capability; required for eIDAS qualified timestamps |
| W3C PROV-O | Provenance ontology | Provenance barrier | 🔧 | PROV-O serialiser is Part 2 capability |
| W3C VC-DM 2.0 | Verifiable Credentials | OR-Set consent receipts | 🔧 | VC-DM 2.0 integration is Part 2 |
| IETF AAT draft | Agent audit trail format | IETF AAT export adapter (aevum-sdk) | ✅ | Draft; not yet RFC |
| OTel GenAI semconv | AI event telemetry | aevum-llm OTel mapper | ⚠️ | Spec in Development (not stable); tracked at v1.27.0-experimental |
| NERC CIP-007-6 R4 | Security event monitoring, 90-day online retention | AuditEvent stream | ⚠️ | 90-day retention config; 1-hour incident reporting external |
| FERPA §99.32 | Disclosure log for educational records | Sigchain (ingest/query events) | ✅ | |
| Sigstore Rekor v2 | External chain witnessing | aevum-publish complication | 🔧 | Requires SPIFFE/Rekor deployment; hashedrekord API format should be verified against rekor-tiles CLIENTS.md before production use |

---

## Retention Period Conflicts

When a deployment is subject to multiple standards, take the longest floor:

| Scenario | Standards | Longest Retention Floor |
|----------|-----------|------------------------|
| Healthcare AI (US) | HIPAA 6yr + FDA 2yr | 6 years |
| Payment processing AI | PCI DSS 1yr + SOX 7yr | 7 years |
| EU high-risk AI | Art. 18 10yr (tech docs) + Art. 19/26 6mo (logs) | 10 years for docs; 6 months for operational logs |
| Financial services AI (NY) | NYDFS 5yr + FINRA 6yr + SOX 7yr | 7 years |
| EU financial AI | DORA (no fixed period) + MiFID II 5yr + GDPR minimal | 5 years minimum |

GDPR Art. 5(1)(e) storage limitation conflicts with all longer-retention
standards when logs contain PII. Resolution: retain the log entry (with hash
of content); delete the PII payload on GDPR schedule. The chain retains
integrity; the content is tombstoned.

---

## Out-of-Scope Items (Intentional)

These are NOT Aevum kernel responsibilities:

- Execution sandboxing / runtime network enforcement
- SIEM alerting and anomaly detection
- Report generation (DORA reports, SEC 8-K, SOX certifications)
- Risk assessment workflows (Colorado AI Act, CCPA/CPRA)
- ROPA document generation
- De-identification (NIST SI-19)
- Session capture (NIST AU-14)
- Cross-organizational log federation (AU-16) — Part 2 scope
