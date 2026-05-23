# Lessons Learned — v0.6.0

This document captures lessons from the v0.6.0 development cycle
(Phases G, A, B, C, D, E, M, DOC, UX, F). Each entry follows a
fixed structure so future sessions can apply the lesson without
reconstructing context.

Format per entry: What happened → Why it happened → What changed as a
result → What to watch for in v0.7.0.

---

## L-01 — Pre-flight CI discipline

**What happened:** Phase DOC required 4 CI fix PRs after merge. The
pipeline failed on pip-audit and mkdocs build --strict checks that
were not run locally before pushing.

**Why it happened:** The session pushed without verifying the full
pre-flight checklist. pip-audit and mkdocs --strict were treated as
CI-only checks rather than local gates that must pass before the push.

**What changed:** A full pre-flight checklist was added to the ENHANCEMENT.md
template and reinforced in every subsequent session document. The EXECUTION.md
template now explicitly lists mkdocs build --strict and pip-audit as required
before any commit to main.

**Watch for in v0.7.0:** Run pip-audit and mkdocs build --strict locally before
every push. Do not treat CI as the first place a check runs — treat it as
verification that the local check was already correct.

---

## L-02 — Read before build

**What happened:** The Phase UX session document initially included tasks to
create robots.txt, JSON-LD, OG tags, ADOPTERS.md, and a demo backend. All of
these already existed in the repository.

**Why it happened:** The session document was written from plan assumptions
rather than verified repository state. The author assumed the gaps from the
plan description without reading the actual files first.

**What changed:** A recalibration pass was run before Phase UX proceeded. A
READ BEFORE WRITING section was added to the session document, listing files
to inspect before creating new ones.

**Watch for in v0.7.0:** Every session document must include a READ BEFORE
WRITING section listing files to check first. If you are about to create a
file, verify it does not exist first. If it exists, read it cold before
deciding whether to update or replace it.

---

## L-03 — Maintenance template first-pass errors

**What happened:** Phase M Part 2 (MAINTENANCE_THREAT_MODEL.md) had incorrect
scenarios in the first pass. All five scenarios required correction before
acceptance.

**Why it happened:** The scenarios were generated from assumptions about the
maintenance workflow rather than from reading the actual maintenance templates
and existing threat model content cold.

**What changed:** The correction was made before acceptance and noted in the
Phase M gate report. The lesson reinforces the READ BEFORE WRITING rule:
existing documents must be read fully before generating content that references
or extends them.

**Watch for in v0.7.0:** Read existing docs cold before generating any content
derived from them. This applies especially to maintenance templates,
THREAT_MODEL.md, and KNOWN_UNKNOWNS.md — all of which have accumulated
detail that is easy to get wrong from memory or assumptions.

---

## L-04 — Workflow without secrets prerequisite

**What happened:** The deploy-demo.yml workflow triggered on merge to main
when demo/** changed, but the FLY_API_TOKEN_DEMO secret had not yet been
created in the repository. The workflow ran and failed on the missing secret.

**Why it happened:** The workflow was committed without a secrets-prerequisite
note. The manual setup step (creating the secret) was documented in the
deployment guide but not surfaced in the workflow file header or in the
PR description.

**What changed:** The manual steps list was maintained throughout Phase UX
and the failure was flagged in the Phase UX gate report. The lesson: any
workflow that requires a repository secret must document that prerequisite
in the workflow file header comment, not only in a separate deployment guide.

**Watch for in v0.7.0:** Any new GitHub Actions workflow that requires a
repository secret must include a comment block at the top of the file
listing the required secrets and the manual steps to create them before
the first trigger. Do not assume the deployment guide will be read before
the workflow fires.

---

## L-05 — Stale enhancements.md (founding lesson)

**What happened:** Phase G found that enhancements.md had Phases 1–4 of
the aevum-maintainer work listed as Backlog when they had already been
completed. The investigation gate spent time on items that were done.

**Why it happened:** Work was completed without updating the tracking
document. enhancements.md drifted from reality over time.

**What changed:** A pre-flight backlog audit was added to EXECUTION.md.
The audit reads enhancements.md against CHANGELOG.md before the session
begins. Any item listed as Backlog that appears in CHANGELOG.md as shipped
is removed or marked complete.

**Watch for in v0.7.0:** Run the backlog audit at the start of every session
that touches enhancements.md. Check CHANGELOG.md first. Do not trust
backlog status without verifying against delivered work.

---

## L-06 — Investigation gate prevented wasted implementation

**What happened:** Phase G ran an investigation gate before any implementation.
The gate confirmed: Cedar p99 latency 496µs (within the < 1ms target), DX
onboarding timing 9.9 seconds (well under the 15-minute gate), all five
unconditional barriers confirmed in place, all adversarial probes passed.

**Why it mattered:** The gate findings meant no implementation phase required
a design reversal. Every subsequent phase built on confirmed assumptions rather
than discovered ones. Eleven phases completed without a single reversal.

**What changed:** The investigation gate is now a named, required step in every
L-scoped or multi-phase enhancement session. The gate report is a deliverable,
not a formality.

**Watch for in v0.7.0:** Never skip the investigation gate for L-scoped or
multi-phase work. The cost of the gate is always lower than the cost of a
design reversal mid-implementation. The Phase G result — no reversals across
11 phases — is evidence that the gate works.

---

*Document created: v0.6.0 Phase F (Part 2), 2026-05-23.*
*Minimum entries: 6. Additional lessons may be appended as v0.7.0 proceeds.*
