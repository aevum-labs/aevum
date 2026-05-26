# ISO/IEC 42001:2023 Annex A — Aevum Evidence Pack Mapping

*Last updated: 2026-05-26. This document does not constitute legal advice.
Engage a qualified ISO 42001 certification body for formal audit preparation.*

This table maps every ISO/IEC 42001:2023 Annex A control to the Aevum artifact
that satisfies it. Use this as the evidence index for ISO 42001 auditors.

---

## Evidence table

| Annex A Control | Control Description | Aevum Artifact | Artifact Location |
|----------------|---------------------|----------------|-------------------|
| A.2.2 | AI policy | Cedar policies + Rego policies | `packages/aevum-core/src/aevum/core/policies/` |
| A.4.1 | Resource management for AI systems | `uv.lock` pinned deps + SBOM | Release artifacts (GitHub releases) |
| A.5.1 | AI system impact assessment records | FRE 902(13) bundle + SQLite receipt store | `docs/legal/fre-902-13-certification-template.md`; `~/.aevum/receipts.db` |
| A.6.1 | AI system objectives and planning | `CLAUDE.md` + project planning documents | Repository root |
| A.6.2.3 | Training data documentation | `model_identity_hash` in every receipt | `AevumReceipt` schema |
| A.6.2.5 | Explainability by design | `prompt_hash` + provenance chain in receipt | `AevumReceipt` schema |
| A.6.2.6 | Human oversight | `human_override_action` + `TRANSITION_DEMAND` sigchain events | `AevumReceipt`; episodic ledger |
| A.6.2.8 | AI system event logs | `SqliteReceiptStore` + SCITT receipts | SQLite store; transparency log |
| A.7.1 | Verification and validation | Conformance suite 11/11 | `aevum-conformance` repository |
| A.8.1 | AI system transparency | SCITT profile + receipt schema | `docs/standards/scitt-profile.md` |
| A.9.1 | Monitoring of AI systems | `ExceedanceDetector` + FOQA/OTel metrics | `aevum-otel` package |
| A.10.1 | Incident management | AI Incident Investigation Workflow | `docs/legal/ai-incident-investigation-workflow.md` |

---

## Audit evidence checklist

For each control, the auditor should request the following artifacts:

### A.2.2 — AI policy

- [ ] Cedar policy bundle in use at time of audit (`*.cedar` files)
- [ ] OPA Rego bundle (if OPA sidecar configured)
- [ ] Policy version history (git log for `policies/` directory)
- [ ] Evidence that `NullPolicyEngine` is not used in production (env/config audit)

### A.4.1 — Resource management

- [ ] `uv.lock` from production deployment (pinned dependency graph)
- [ ] SBOM (Software Bill of Materials) — generated from `uv.lock`
- [ ] Evidence that `AEVUM_DEV=1` is not set in production

### A.5.1 — Impact assessment records

- [ ] FRE 902(13) certification document (signed)
- [ ] Receipt bundle covering the audit period
- [ ] `aevum verify-receipt` output demonstrating chain integrity

### A.6.1 — Objectives

- [ ] `CLAUDE.md` / project charter
- [ ] Five public function definitions (frozen invariants documentation)

### A.6.2.3 — Training data documentation

- [ ] Sample receipts showing `model_identity_hash` field populated
- [ ] Model identity resolution procedure (hash → model version mapping)

### A.6.2.5 — Explainability

- [ ] Sample receipts showing `prompt_hash` field
- [ ] Provenance chain for representative ingestion events (chain of custody)

### A.6.2.6 — Human oversight

- [ ] Sample `TRANSITION_DEMAND` sigchain entries
- [ ] Sample `human_override_action` entries
- [ ] Autonomy level configuration (`autonomy.cedar`) in production
- [ ] Evidence that `review()` function is called before consequential irreversible actions

### A.6.2.8 — Event logs

- [ ] `SqliteReceiptStore` file with representative entries
- [ ] SCITT inclusion proofs (if transparency log configured)
- [ ] `verify_sigchain()` output showing chain integrity

### A.7.1 — Verification and validation

- [ ] Conformance suite run report (11/11 passing)
- [ ] CI test run showing 1328 passing tests
- [ ] `docs/conformance_report.txt`

### A.8.1 — Transparency

- [ ] `docs/standards/scitt-profile.md` — receipt format documentation
- [ ] Published issuer public key (URL and fingerprint)

### A.9.1 — Monitoring

- [ ] `ExceedanceDetector` configuration (if deployed)
- [ ] OTel metric export sample (if `AevumOTelBridge` configured)
- [ ] Evidence that `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` default is `false`

### A.10.1 — Incident management

- [ ] `docs/legal/ai-incident-investigation-workflow.md` — procedure document
- [ ] Evidence of at least one incident investigation drill (table-top or real)
- [ ] EU AI Act Art. 73 notification template (if Annex III system)

---

## Generating the evidence bundle

To produce a complete evidence bundle for an auditor:

```bash
# 1. Verify sigchain integrity
aevum verify-receipt --hash <session_receipt_hash>

# 2. Export receipts for audit period
# (use kernel API or SqliteReceiptStore query in production)

# 3. Run conformance suite
uv run pytest packages/ --tb=short -q -m "not integration"

# 4. Generate SBOM from lock file
# (use your preferred SBOM tool: cyclonedx-py, syft, etc.)

# 5. Export policy bundle version
git log --oneline packages/aevum-core/src/aevum/core/policies/ | head -5
```

Assemble the outputs together with the signed FRE 902(13) certification
(`docs/legal/fre-902-13-certification-template.md`) as the complete evidence pack.

---

## See also

- `docs/legal/fre-902-13-certification-template.md` — US federal court certification
- `docs/legal/ai-incident-investigation-workflow.md` — incident investigation procedure
- `docs/learn/compliance-mapping.md` — cross-standard compliance table
- `docs/standards/scitt-profile.md` — SCITT receipt format
