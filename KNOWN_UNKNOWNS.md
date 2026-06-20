# Known Unknowns

This document records questions that are intentionally deferred: either
because the answer requires more investigation than is appropriate now, or
because the design decision depends on data we do not yet have. Each entry
includes the item ID, the question, the reason for deferral, and the
condition that would cause it to be revisited.

This is a living document. Entries are removed when resolved and added when
new deferral decisions are made. Resolved entries move to CHANGELOG.md.

---

## V07-MLDSA65: ML-DSA-65 Post-Quantum Signing (CLOSED implementation / OPEN validation)

**Item:** V07-MLDSA65 — confirmed closed for implementation in Session 13

**CLOSED (implementation):** ML-DSA-65 dual-signing is implemented in `DualSigner` since
v0.4.0, confirmed present in 17 files. `DualSigner` in
`packages/aevum-core/src/aevum/core/signing.py` signs every sigchain entry with
BOTH Ed25519 (PyNaCl) AND ML-DSA-65 (liboqs-python). Both signatures must be valid;
neither alone is sufficient. `DualSigner` is wired into `Sigchain` as an optional
`dual_signer` constructor argument — it is not the default (the default is
`InProcessSigner`, Ed25519 only). See `docs/architecture/signing.md`.

**CLOSED (export control):** EAR §742.15 supplemental notification for ML-DSA-65
(FIPS 204, Module-Lattice-Based Digital Signature Algorithm) filed 2026-05-24.
See SECURITY.md.

**OPEN (FIPS 140-3 module certification):** ML-DSA-65 implements the FIPS 204
algorithm standard. FIPS 140-3 module certification (a security certification for
cryptographic modules, distinct from algorithm standardization) has not been
obtained. FIPS 140-3 is out of scope until a regulated customer requires it.

**OPEN (deployment):** liboqs native `.so` must be pre-installed in production
environments — it is NOT bundled with the `liboqs-python` pip package.
See `docs/deployment/liboqs.md` for platform-specific setup instructions.

**Closed:** Session 13 (2026-05-26) — implementation confirmed.

---

## V07-ZIZMOR: GitHub Actions Security Scan (CLOSED — Session 12A)

**Item:** V07-ZIZMOR — closed in Session 12A

**Resolution:** zizmor added to CI (ci.yml zizmor job). SARIF results visible in
GitHub Security → Code scanning tab. The v0.5.0 CHANGELOG claim that zizmor was
previously added was inaccurate — it was never present in any workflow file.
Verified absent across all 14 workflow files before adding.

zizmor runs on every push/PR, uploads findings as SARIF to Code Scanning. The job
does not fail on findings (advisory mode); critical findings appear in the Security
tab for human review. SHA used: `github/codeql-action/upload-sarif@458d36d7d4f47d0dd16ca424c1d3cda0060f1360` (v3, same as scorecard.yml).

**Closed:** Session 12A (2026-05-26).

---

## V07-AGENT-CONTEXT: gen_ai.agent.name/id Not Emitted by OTel Bridge (Open — v0.7.0)

**Item:** V07-AGENT-CONTEXT — deferred in Session 3B

**Question:** Why are gen_ai.agent.name and gen_ai.agent.id not emitted by the
aevum-otel bridge?

**Root cause:** AuditEvent does not carry structured agent identity at OTel bridge
emit time. The `actor` field exists but is a free-form string (not a structured
agent_id/agent_name pair). The OTel GenAI semantic conventions (gen_ai.agent.name,
gen_ai.agent.id) require a structured identity that is not currently available.

**Resolution path:** Wire agent_id from AevumReceipt into spans once the receipt
store is queryable at OTel span emit time. The receipt contains `agent_id` as a
structured field, but the bridge currently does not have access to the receipt at
span emit time (it only receives AuditEvents, not AevumReceipts).

**Target:** v0.8.0 or when receipt store is connected to the OTel bridge. The
ExceedanceDetector (Session 3B) now processes AevumReceipt objects — the same
pattern can be applied to the OTel bridge when the design is ready.

**Last confirmed:** Session 3B (2026-05-25).

---

## V07-ADAPTER-DRIFT: Adapter Drift Tests Use importorskip Guards (CLOSED — Session 1A)

**Item:** V07-ADAPTER-DRIFT — confirmed in Session 1A gate

**Question:** Are the adapter drift tests (10 tests) skipping in CI because
the optional framework packages (Anthropic SDK, LangChain, etc.) are absent
from the test environment? Is this a test failure or expected behavior?

**Resolution (confirmed Session 1A):** CLOSED. All 10 adapter drift tests use
`pytest.importorskip()` guards. Skip is intentional — optional framework packages
not installed in CI. Confirmed in Session 1A pre-flight investigation.

The guards are:
```python
anthropic = pytest.importorskip("anthropic")
langchain = pytest.importorskip("langchain")
# etc.
```

**Action required:** None. Adapter drift tests are verified manually when
adapter package updates are published. In a future CI configuration with
optional-extras test environments, these tests will run against real adapters.

**Last confirmed:** Session 1A gate (2026-05-25). Status confirmed CLOSED Session 3B.

---

## G-25: Cedar vs. OPA Policy Role Separation (RESOLVED — Phase E)

**Item:** G-25 — resolved in Phase E, spec/09-policy.md

**Question:** Are Cedar and OPA competing policy engines, or do they serve
different purposes in Aevum's policy architecture?

**Resolution:** Cedar and OPA are complementary and non-competing.
Cedar handles entity-based access control decisions in-process (can this
principal perform this action on this resource?). OPA handles content-based
policy via HTTP sidecar (does this payload satisfy HIPAA minimum-necessary,
GDPR purpose limitation, or custom operator rules?). Cedar's formal
authorization semantics are not suitable for arbitrary payload inspection;
OPA's Rego cannot natively model principal-resource entity graphs. A
Cedar-only deployment is fully supported and covers all five unconditional
barriers and all ABAC decisions. OPA is optional and additive.

**Documented in:** `docs/spec/09-policy.md` — Cedar + OPA decision architecture.

---

## E-07-PUB: ADR-008 cross_chain_ref Reference Architecture Publication (Deferred)

**Item:** E-07-PUB — flagged in Phase E for future publication

**Question:** Should the `cross_chain_ref` design from ADR-008 (W3C Trace
Context + cryptographic cross-chain causal linking) be published as a
reference architecture at a conference or in a blog post?

**Why deferred:** The design is architecturally mature and novel, but no
external publication has been drafted. Publishing requires editorial review,
coordination with the Aevum Labs communications plan, and a determination of
the target venue (USENIX Security, IEEE S&P, SOSP, or practitioner blog).

**Condition for revisitation:** When v0.7.0 ships and includes multi-agent
A2A integration (Phase 6), the design will have production validation.
At that point, a draft should be written for a practitioner venue.

**Related:** ADR-008, docs/learn/architecture.md (reference architecture note)

---

## D-17: Six-Barrier Resource Ceiling (Deferred)

**Item:** D-17 — Deferred to KNOWN_UNKNOWNS.md only (no build task)

**Question:** Should the five unconditional barriers be extended to a sixth
barrier that enforces a resource ceiling — capping the total compute, token
spend, or external API calls that a single agent session can make before
requiring human review?

A resource ceiling would close the gap between Aevum's current five barriers
(which govern *what* can be accessed) and the question of *how much* can be
consumed (runaway agent spend, denial-of-wallet attacks, model cost exhaustion).

**Why deferred:**

1. **No canonical metric.** The right resource unit is not obvious: token
   count, wall-clock time, external call count, and cost-in-dollars all have
   different measurement complexities and deployment dependencies.

2. **Deployment-specific thresholds.** A reasonable ceiling for a batch
   analytics agent is catastrophic for a real-time user-facing agent. A
   hardcoded unconditional barrier would need per-deployment configuration,
   which conflicts with the "unconditional" property of the five existing
   barriers.

3. **Policy vs. barrier.** A resource ceiling may be better expressed as a
   Cedar policy (configurable, per-principal) rather than a hardcoded barrier.
   This is an architectural question that requires the policy engine to be
   more mature before the right answer is clear.

4. **No production incident data.** We have not observed a runaway-spend
   incident in Aevum deployments. The theoretical risk is understood; the
   practical severity and frequency are not.

**Condition for revisitation:** If a runaway-spend incident is observed in
production, or if a regulation explicitly requires a configurable cost ceiling
as a barrier (not a policy), this item should be promoted to a build task.

**Related:** THREAT_MODEL.md — "What Aevum Does Not Protect Against" (resource
exhaustion is currently listed as out of scope).

---

## D-FIPS: FIPS 140-3 Deployment Guide (Deferred)

**Item:** FIPS 140-3 guide — deferred from v0.6.0 Phase D

**Question:** How should operators configure Aevum for FIPS 140-3 validated
deployments?

Aevum's default `InProcessSigner` uses Ed25519 via the Python `cryptography`
package. Whether a given build of the `cryptography` package uses a
FIPS 140-3 validated module depends on the operating system and OpenSSL
configuration — it is not guaranteed by default.

**Why deferred:**

1. **FIPS validation is environment-specific.** The answer differs between
   RHEL with `fips=1` in the kernel, Ubuntu FIPS, and custom builds.
   A single guide cannot cover all cases accurately.

2. **ML-DSA-65 FIPS 140-3 module certification not yet obtained.** ML-DSA-65
   (FIPS 204 algorithm standard) is implemented in `DualSigner` since v0.4.0
   (see V07-MLDSA65). FIPS 140-3 module certification for the post-quantum
   signing path is out of scope until a regulated customer requires it.

3. **No regulated customer requiring FIPS has been onboarded.** Writing a
   guide without a concrete deployment to validate it against risks being
   inaccurate.

**Condition for revisitation:** When the first regulated customer requiring
FIPS 140-3 is onboarded, this item becomes a P0 build task.

**Interim guidance:** THREAT_MODEL.md — "HIPAA (healthcare, PHI)" notes that
Aevum's default in-process Ed25519 is not FIPS 140-3 validated. Use an HSM
or KMS-backed signer for FIPS-required deployments.

---

## G-23: Getting-Started Guide Timing (Deferred)

**Item:** G-23 from Phase G gate investigation

**Question:** What is the actual time from `pip install aevum-core` to a
working governed ingest call, measured in a clean isolated environment?

**Why deferred:** Requires a clean pip install in an isolated environment
(not the development workspace). The measurement depends on network speed,
PyPI CDN, and Python environment setup time — not something that can be
measured reproducibly in CI without a dedicated job.

**Condition for revisitation:** When the getting-started guide rewrite (B-15)
is prioritized, this measurement should be taken as part of validating the
"under 5 minutes" claim.

---

## G-DX: DX Onboarding Timing (RESOLVED — Phase G)

**Item:** G-DX — resolved in Phase G investigation gate

**Question:** Is the DX onboarding time (pip install to first governed ingest
call) within the 15-minute gate required for the getting-started guide to be
viable?

**Resolution:** Confirmed acceptable. Phase G gate measured 9.9 seconds for
a guided onboarding flow in a prepared environment. Well under the 15-minute
gate. The getting-started guide is viable as written; no friction-reduction
sprint is required before v0.7.0 DX work.

Note: G-23 (clean-install measurement from PyPI CDN) remains open as a
separate item.

**Documented in:** Phase G gate report (2026-05-23).

---

## G-BACKLOG: enhancements.md Staleness (RESOLVED — Phase G)

**Item:** G-BACKLOG — found and resolved in Phase G investigation gate

**Question:** Is enhancements.md an accurate representation of the current
backlog, or has completed work been left in Backlog status?

**Resolution:** Phase G found Phases 1–4 of aevum-maintainer listed as
Backlog when they were complete. Items were corrected and a pre-flight
backlog audit was added to EXECUTION.md. enhancements.md is now accurate.

**What changed:** Pre-flight backlog audit added to EXECUTION.md Phase 0.
Lesson captured in LESSONS_LEARNED.md (L-05).

---

## V07-STAINLESS: Stainless SDK Unification Risk (Open — v0.7.0)

**Item:** V07-STAINLESS — flagged in Phase DOC anthropic.md guide

**Question:** The Anthropic SDK surface may change significantly in H2 2026
if the Stainless unification ships. How much of AevumAnthropicAdapter will
need to change, and what is the migration cost?

**Why deferred:** The Stainless unification has not shipped as of v0.6.0.
AevumAnthropicAdapter wraps the current message-creation interface; if the
SDK surface changes materially, the adapter wrapping point may move.

**Condition for revisitation:** At v0.7.0 start, check Anthropic SDK
changelog. If Stainless unification has shipped, run an investigation gate:
what changed, what breaks, what is the migration scope?

**Related:** docs/learn/guides/anthropic.md (Stainless migration risk note).

---

## V07-VAULT: VaultTransitSigner Live Vault Validation (CLOSED — Session 4)

**Item:** V07-VAULT — CLOSED. VaultTransitSigner confirmed functional against
live Vault 2.0.0 dev server on Windows 10 PC. Sign/verify round-trip passes.
Integration tests added (skipif VAULT_ADDR not set).
CLI command: `aevum vault-check`. Closed: Session 4 (2026-05-26).

**Bug fixed:** `prehashed: true` in Vault Transit sign call was rejected by Vault 2.0.0
ed25519 keys ("only Pure Ed25519 signatures supported, prehashed must be false").
Fixed to `prehashed: false`. `verify()` method was also missing — added with Vault
Transit verify endpoint. Base64 encoding fixed: Vault uses standard base64 (`+`/`/`),
not URL-safe (`-`/`_`).

**Files modified:**
- `packages/aevum-core/src/aevum/core/audit/signer.py` — prehashed fix, verify() added
- `packages/aevum-core/tests/test_vault_transit_signer.py` — 8 integration tests added
- `packages/aevum-cli/src/aevum/cli/app.py` — vault-check command added
- `docs/deployment/vault-setup.md` — created

---

## V07-OTEL-SEMCONV: gen_ai.system → gen_ai.provider.name Migration (CLOSED — Session 3A)

**Item:** V07-OTEL semconv attribute fix — found in v0.7.0 investigation gate (2026-05-24)

**Resolution:** gen_ai.provider.name is now emitted as the primary attribute on every
ingest event that previously used gen_ai.system. gen_ai.system is emitted in dual-emit
mode for backward compat (default on). To disable dual-emit and emit only the current
attribute: set `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental`.

Span naming in AevumOTelBridge (`aevum.{event_type}`) is correct for its purpose
(audit event spans, not GenAI client spans). No change needed there.

**Files modified:** `packages/aevum-core/src/aevum/core/functions/ingest.py`,
`packages/aevum-core/tests/test_functions.py`, `.env.example`

**Closed:** Session 3A (2026-05-25).

---

## V07-OTEL: Grafana Tempo + Langfuse AevumOTelBridge Live Testing (Open — v0.7.0)

**Item:** V07-OTEL — documented in Phase DOC otel-bridge.md

**Question:** Do the AevumOTelBridge setup instructions for Grafana Tempo and
Langfuse work against live instances? Both backends are noted in the docs as
"setup notes only — not tested against a live instance."

**Why deferred:** Live backend testing requires running infrastructure that
was not provisioned during Phase DOC.

**Condition for revisitation:** Before the OTel bridge is promoted in any
adopter-facing material as production-ready, validate both backends. Grafana
Tempo via the official Docker Compose quickstart; Langfuse via their hosted
tier.

---

## V07-OPENCLAW: OpenClaw Adapter (Open — deferred from v0.6.0)

**Item:** V07-OPENCLAW — deferred from Phase B adapter matrix

**Question:** Can an AevumOpenAIAgentsAdapter be built that works reliably
with the OpenAI Agents SDK hook interface? Is the hook API stable following
the OpenAI acquisition?

**Why deferred:** OpenAI's post-acquisition SDK governance and the hook API
stability are unknown. Building against a moving target risks a rebuild on
the first SDK update.

**Condition for revisitation:** At v0.7.0 start, check OpenAI Agents SDK
changelog for the prior 90 days. If the hook API has been stable across
three releases, begin Stage 1.

---

## V07-BARRIER-FNR: Crisis Barrier False Negative Rate (Open — v0.7.0)

**Item:** V07-BARRIER-FNR — flagged in Phase G adversarial probe results

**Question:** What is the false negative rate of the five unconditional
barriers against novel adversarial inputs in production, beyond the probes
run in Phase G?

**Why deferred:** Phase G adversarial probes all passed (PASS on all five
barrier types). However, the probe set is fixed and was designed against
known attack patterns. Real-world attack variety is unknown.

**Condition for revisitation:** If a crisis barrier bypass is observed in
production — even in testing — this becomes a P0 investigation. Otherwise,
review the probe set at v1.0 with fresh adversarial inputs.

**Related:** THREAT_MODEL.md — adversarial prompt section.

---

## V07-OXIGRAPH: oxigraph Graph Store Necessity (Open — v0.7.0)

**Item:** V07-OXIGRAPH — operational question, no production data

**Question:** Is aevum-store-oxigraph a necessary production deployment option,
or does aevum-store-postgres cover all real-world use cases?

**Why deferred:** No production deployments have run long enough to determine
whether the oxigraph store's in-process speed advantage matters at real
workload. The decision to keep vs. deprecate the oxigraph store requires data.

**Condition for revisitation:** After three months of demo.aevum.build traffic,
examine whether any adopter has asked about the oxigraph store for production.
If no production interest, consider deprecation in v1.0.

---

## V07-CONFORMANCE: Conformance Suite Completeness (VERIFIED — 2026-06-06)

**Item:** V07-CONFORMANCE — verified in cedar-pin-conformance session (2026-06-06)

**Status:** VERIFIED — 11/11 invariants passing (suite has grown from 74 to
encompass 11 top-level invariant groups since the original 9/9 target was set).

**Evidence:**
```
uv run python -c "from aevum.conformance.suite import ConformanceSuite; \
  r = ConformanceSuite().run_all(); print(r.passed_count, '/', r.total_count)"
# → 11 / 11
```
Verified against cedarpy 4.8.4 (constraint ~=4.8.0, lockfile version 4.8.4).
Full pytest suite: 1382 passed, 102 skipped, 0 failed.

**Notes:** Re-verify before every PyPI release. Gate check in
maintenance/templates/EXECUTION.md.

**Why originally deferred:** The 74-test suite covered the five public functions
and all five unconditional barriers. Coverage of multi-agent interaction patterns
and edge-case replay scenarios was unknown.

**Condition for revisitation:** Run a coverage gap analysis against the spec at
v0.8.0 start. Identify any normative "MUST" or "MUST NOT" in the spec that has
no corresponding conformance test.

---

## V07-COMMUNITY: External Contribution Pipeline (Open — v0.7.0)

**Item:** V07-COMMUNITY — unknown until v0.6.0 is public

**Question:** Will v0.6.0 generate external GitHub contributions? If so, does
the project have a functional first-PR review process and response SLA?

**Why deferred:** CONTRIBUTING.md exists, but no external PRs have arrived.
The process cannot be validated without a real contribution.

**Condition for revisitation:** Monitor GitHub Issues and PRs after v0.6.0
PyPI release. If an external PR arrives within 30 days, run a community
infrastructure working session.

---

## V07-TRADEMARK: Trademark Search Not Yet Conducted (Open — v0.7.0)

**Item:** V07-TRADEMARK — flagged in Phase UX SECURITY.md update

**Question:** Is "Aevum" available for trademark registration in Class 9 and
Class 42 (USPTO) and the equivalent EUIPO classes?

**Why deferred:** The TESS and EUIPO searches are manual tasks that require
time to run and review. Neither has been initiated as of v0.6.0.

**Condition for revisitation:** Must be resolved before v1.0. Initiate the
search during v0.7.0 so results are available before v1.0 planning begins.
Trademark searches typically take days to complete but require weeks to act on
if a conflict is found.

**Related:** SECURITY.md — trademark status section; TRADEMARK.md.

---

## V07-OG-IMAGE: OG Image Placeholder (Open — v0.7.0)

**Item:** V07-OG-IMAGE — flagged in Phase UX web presence review

**Question:** Is there a real Open Graph image asset for aevum.build, or is
the current og:image reference pointing to a placeholder that has not been
commissioned?

**Why deferred:** Commissioning a real OG image requires design work outside
the scope of the v0.6.0 documentation phases. The placeholder avoids a broken
og:image tag but does not produce a recognizable preview when shared.

**Condition for revisitation:** Before any public launch announcement or v1.0,
commission and deploy a real OG image. The spec: 1200×630px, SVG or PNG,
consistent with the aevum.build color scheme.

---

## V08-CONSENT-FLOWTHROUGH: Consent Flow-Through to Derived Artifacts (Deferred — toward v1.0)

**Item:** V08-CONSENT-FLOWTHROUGH — was the stated v0.8.0 plan anchor; v0.8.0
shipped the black-box crypto triad instead. Never tracked here until now.

**Question:** How should a consent revocation reach artifacts *derived* from
governed data (RAG embeddings, vector representations) that live in an external
store?

**Why it matters:** Crypto-shredding destroys the subject's DEK, so the source
plaintext becomes unrecoverable — but an embedding already computed from that
plaintext is itself plaintext in some vector store, and shredding the DEK does
not reach it. This is exactly why "revocation-on-retrieval" is required: you
cannot shred what has already been derived, so retrieval must be gated instead.

**Why deferred (not descoped):** Genuine, defensible differentiator — no
competitor binds consent to derived artifacts. Deferred because there is no
embedding/retrieval surface in Aevum to design against yet, and Aevum is the
governance membrane, not a datastore.

**Shape (intended):** NOT an Aevum-owned vector store and NOT another *Store
protocol. Unlike GraphStore/ReceiptStore (which Aevum drives), this is inverted:
the adopter's retrieval path calls *into* Aevum — a barrier/middleware-style
`consent_check(subject, purpose) -> allow | deny | shred` hook the adopter wires
in, plus one reference adapter. Bring-your-own-infrastructure, consistent with
the Protocol-seam architecture (ADR-004 signer, ADR-005 policy).

**Condition for revisitation:** When a concrete RAG/retrieval adopter exists to
design the contract against. Target: v1.0 differentiator.

**Related:** ADR-003 (OR-Set consent), Barrier 3 (Consent), crypto-shred in
consent/ledger.py.

---

## V08-WAL-SHRED: SQLite WAL Checkpoint + Secure-Delete on Rotation (Deferred — v0.9.0)

**Item:** V08-WAL-SHRED — code TODO at sqlite_store.py:246, not previously
tracked here.

**Question:** After rotate_operational() and on the consent crypto-shred path,
the WAL is not checkpointed/truncated and rows are not secure-deleted, so the
-wal/-shm sidecars retain plaintext after process exit.

**Why it matters:** Undercuts the deletion-honesty and GDPR crypto-shred
guarantees — data treated as gone can persist in the sidecar files.

**Fix shape:** PRAGMA wal_checkpoint(TRUNCATE) + secure_delete (or explicit
VACUUM) on the rotation/shred paths. Small change, but it touches storage and
carries a security claim — warrants its own gate; expect test churn.

**Condition for revisitation:** v0.9.0 (folded here per maintainer decision
2026-06-14, in lieu of opening a v0.8.1).

---

## Conformance Suite

Status: VERIFIED
Date: 2026-06-06
Result: 11/11 invariants passing (gate required ≥ 9/9)
Evidence: `uv run python -c "from aevum.conformance.suite import ConformanceSuite; r = ConformanceSuite().run_all(); print(r.passed_count, '/', r.total_count)"`
Notes: Re-verify before every PyPI release. Gate check in maintenance/templates/EXECUTION.md.
cedarpy version at verification: 4.8.4 (constraint ~=4.8.0)

---

## HO-SEC-SKIP: aevum-llm / aevum-maintainer pip-audit Skips Are Expected (CLOSED — HO-SEC)

**Item:** HO-SEC-SKIP — closed during the v0.8.1 CVE floor-raise + check-script
hardening pass

**Question:** Why does `pip-audit` report "Dependency not found on PyPI and
could not be audited" for `aevum-llm` and `aevum-maintainer`? Is this a gap
that needs investigation?

**Resolution:** Expected, not a gap. `aevum-llm` is a tombstone package and
`aevum-maintainer` is a private workspace package — both are intentionally
unpublishable to PyPI, so `pip-audit` cannot resolve them and correctly
reports a skip rather than a finding. `scripts/check-security.sh` now parses
`pip-audit -f json` and fails only when the parsed vulnerability list is
non-empty; skip-reason entries never fail the check.

**Action required:** None. Do not re-investigate these two skip lines as a
security gap in future sessions.

**Closed:** HO-SEC session (2026-06-19).

---

## HO-G-TWOSUBJECT: Two-"Subject" Distinction — Consent Data Subject vs. P2-IDENTITY-V2 Principal (Open — v0.8.x)

**Item:** HO-G-TWOSUBJECT — flagged during P2-IDENTITY-V2 (spec
`aevum-signing-v2.md`) implementation

**Question:** `aevum.core.consent.ledger.ConsentLedger` and
`aevum.core.audit.commitment_key_store.CommitmentKeyStore` are structurally
near-identical (SQLite-backed, `PRAGMA secure_delete=ON`, crypto-shred on
destroy, an append-only auditable destroy event) but represent two genuinely
different concepts that both happen to be called "subject" in their home
vocabularies:

- `ConsentLedger`'s **subject** is the GDPR/CCPA data subject — the
  natural person whose personal data is being processed, who has granted or
  withheld consent for a stated purpose (Barrier 3 — Consent).
- P2-IDENTITY-V2's **principal** is the bound credential identity of an
  *actor* — an OIDC `sub`, a SPIFFE ID, or a DID identifying which external,
  authenticated party caused a given signed event (DD1).

In the common case these are different people entirely: the actor who
triggers an `agent.decision` event (a human reviewer, an automated agent
acting on a service identity) is frequently not the data subject whose
record the decision concerns. `CommitmentKeyStore` was deliberately given a
disjoint vocabulary (`scope` / `principal` / `commitment_key_id` — DD8,
never "subject") specifically so the two are not casually conflated in code
or documentation. But the underlying conceptual overlap — two distinct
"who is this event about/from" axes, both crypto-shreddable, both keyed by an
opaque store — is real and not yet resolved into a single mental model or a
shared abstraction (if one should even exist; see D-17-style caution about
premature unification of barrier-adjacent concepts).

**Why it matters:** An operator or auditor reading both stores side by side
could reasonably ask "why are there two near-identical erasure mechanisms?"
without an answer in the docs. If a future feature needs to correlate
"this data subject's records were touched by this principal," the two
vocabularies must compose cleanly without merging — accidentally treating a
`commitment_key_id` lookup as a consent check (or vice versa) would be a
privacy-relevant bug class.

**Condition for revisitation:** When a concrete cross-cutting feature
(e.g. a compliance report correlating data-subject consent state with
principal-bound decisions) needs both stores in the same code path — at that
point, decide explicitly whether a shared `Subject`-adjacent protocol is
warranted or whether the disjoint vocabulary should simply be documented more
prominently (e.g. in CLAUDE.md's terminology table) and left at that.

**Related:** DD1, DD8 (`aevum-signing-v2.md`), Barrier 3 (Consent),
`ConsentLedger.shred()`, `CommitmentKeyStore.destroy()`.

---

## HO-G-ERASURE-SCOPE: CommitmentKeyStore Deployment-Scope Erasure Granularity (Deferred — toward v1.0)

**Item:** HO-G-ERASURE-SCOPE — DD5 design decision flagged during
P2-IDENTITY-V2 implementation, not yet revisited

**Question:** `CommitmentKeyStore` keys are scoped per-deployment (or
per-tenant, depending on how `scope` is used by an integrator), not
per-principal. Destroying a `commitment_key_id` via `destroy()` erases the
ability to confirm or re-derive **every** `principal_commitment` computed
under that key — there is no way to selectively erase a single principal's
commitment while leaving others under the same key confirmable. Is this
coarse, all-or-nothing granularity sufficient for v1.0's anticipated use
cases, or will an integrator need per-principal (or per-credential) erasure
before then?

**Why it matters:** A right-to-erasure request scoped to one external
principal (e.g. "stop being able to confirm any event was caused by this
specific OIDC subject") cannot currently be satisfied without destroying the
entire deployment-scope key — which also erases confirmability for every
other principal under that key. For a deployment with many principals
sharing one commitment key, this is a much blunter instrument than
`ConsentLedger.shred()`'s per-subject granularity.

**Fix shape (if needed):** `principal_commitment_key_id` already identifies
which key produced a given commitment (informational signed field, like
`signer_key_id`), so per-principal granularity needs **no signed-format
change** — it would require `CommitmentKeyStore` to mint one key per
principal (or per some finer-grained scope) rather than one per deployment,
which is purely an operational/store-side decision, not a wire-format one.
This is explicitly noted in the `CommitmentKeyStore` docstring as the
intended future refinement path.

**Condition for revisitation:** When a concrete deployment needs
per-principal erasure (e.g. a multi-tenant SaaS integrator handling
individual right-to-erasure requests against a shared commitment key) — at
that point, evaluate whether the operational cost of one key per principal
is acceptable, or whether a different commitment construction is needed.
Target: v1.0 differentiator, not a v0.8.x blocker.

**Related:** DD5, DD6 (`aevum-signing-v2.md`), `CommitmentKeyStore.destroy()`,
V08-CONSENT-FLOWTHROUGH (a related but distinct erasure-granularity question
for consent-derived artifacts).

---

## v0.7.0 Release — Open Items (carry to v0.7.1)

1. **V07-VAULT:** CLOSED Session 4 (2026-05-26) — sign/verify confirmed, integration tests added, CLI vault-check added
2. **V07-AGENT-CONTEXT:** gen_ai.agent.name/id not yet wired into OTel bridge
3. **EX-10:** Concurrent conflicting tool calls — requires cross-session context
4. **EX-14:** A2A communication failure — requires cross-agent message tracking
5. **ScittTsBackend:** stub only — awaiting ScrAPI RFC (draft-ietf-scitt-scrapi)
6. **liboqs-python FIPS 140-3 module certification:** not yet obtained
7. **codeql-action/upload-sarif v3 deprecation:** advisory until December 2026
8. **Session 12C:** Standards participation actions (IETF SCITT, prEN 18229-1, ISO DIS 24970, PROV-AGENT authors) — human, in progress
