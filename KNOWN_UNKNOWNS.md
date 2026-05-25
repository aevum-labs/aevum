# Known Unknowns

This document records questions that are intentionally deferred: either
because the answer requires more investigation than is appropriate now, or
because the design decision depends on data we do not yet have. Each entry
includes the item ID, the question, the reason for deferral, and the
condition that would cause it to be revisited.

This is a living document. Entries are removed when resolved and added when
new deferral decisions are made. Resolved entries move to CHANGELOG.md.

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

2. **ML-DSA-65 (post-quantum) is not yet implemented.** FIPS 140-3
   validation for the post-quantum migration path (Phase C) is out of scope
   until the migration is complete.

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

## V07-VAULT: VaultTransitSigner Live Vault Validation (Open — v0.7.0)

**Item:** V07-VAULT — documented in Phase G gate report

**Question:** Does VaultTransitSigner work correctly against a real Vault
instance with transit secrets engine enabled? It has been tested only with
mocks.

**Why deferred:** Setting up a live Vault instance in CI requires an
infrastructure decision (Vault dev mode in Docker vs. HashiCorp Cloud).
Neither was provisioned during v0.6.0.

**Condition for revisitation:** When a production deployment requires
HSM-backed signing, this item becomes a P0 build task. For v0.7.0, run a
live validation against Vault dev mode in Docker.

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

## V07-CONFORMANCE: Conformance Suite Completeness (Open — v0.7.0)

**Item:** V07-CONFORMANCE — flagged after 74-test milestone

**Question:** Are the 74 conformance tests sufficient to serve as a regression
baseline for v0.7.0 development, or are there gap areas (replay fidelity,
multi-hop consent chains, cross-package integration) not yet covered?

**Why deferred:** The 74-test suite covers the five public functions and all
five unconditional barriers. Coverage of multi-agent interaction patterns and
edge-case replay scenarios is unknown.

**Condition for revisitation:** At v0.7.0 start, run a coverage gap analysis
against the spec. Identify any normative "MUST" or "MUST NOT" in the spec that
has no corresponding conformance test.

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
