# Known Unknowns

This document records questions that are intentionally deferred: either
because the answer requires more investigation than is appropriate now, or
because the design decision depends on data we do not yet have. Each entry
includes the item ID, the question, the reason for deferral, and the
condition that would cause it to be revisited.

This is a living document. Entries are removed when resolved and added when
new deferral decisions are made. Resolved entries move to CHANGELOG.md.

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
