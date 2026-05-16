AEVUM ENHANCEMENT SESSION
==========================
Role:     Claude Code — implement an agreed, scoped enhancement
Source:   Research Report enhancement proposal (approved by you)

Principle: Claude researches and classifies. Claude Code executes and commits.
           Every enhancement ships with matching documentation.
           The science experiment must remain reproducible after this change.
           Execute the agreed scope faithfully — no more, no less.

==========================
SCOPE GUIDE
==========================
Read the scope level below and follow the matching approach.

S — Small (single session)
    One capability, one or two files, follows an existing pattern.
    Commit everything at the end. Single gate report.

M — Medium (single session with checkpoints, or two sessions)
    Multiple files or packages. New test module. New docs section.
    Checkpoint after core implementation — confirm tests pass and mypy
    is clean before continuing to integration and docs.
    If the session runs long, use CONTINUATION HANDOFF and finish in a second session.

L — Large (multi-session, phased)
    Significant new capability, new package, or major extension of an existing one.
    Define phases before writing a line of code — each phase must be independently
    testable and committable. Use CONTINUATION HANDOFF between sessions.
    review each phase before the next begins.

==========================
ENHANCEMENT BRIEF
==========================
What:       [copy from Research Report]
Why:        [the driver — protocol, compliance, competitive]
Source:     [month of Research Report that proposed this]
Package(s): [which packages this touches]
Scope:      [S / M / L]
Priority:   [NOW / SOON / BACKLOG — and why it was elevated]

==========================
AGREED SCOPE AND PHASES
==========================
(For S: a single implementation note is enough.
 For M/L: define phases before starting. Each phase = independently testable unit.)

Phase 1: [specific deliverable — what passes when this phase is done]
Phase 2: [specific deliverable]
Phase N: [final integration, full docs, acceptance criteria]

Current session: Phase [N]

Example (M):
  Phase 1: Core task streaming in aevum-agent — new StreamingTask class,
            unit tests passing, mypy clean. No server changes yet.
  Phase 2: SSE integration in aevum-server, end-to-end test, docs updated.
  Current session: Phase 1

==========================
CONTEXT
==========================
[3–5 lines: what Aevum currently does in this area, and what the gap is.
 Specific enough that Claude Code does not need to infer the gap.]

==========================
IMPLEMENTATION BRIEF
==========================
[Specific technical guidance for this session's phase.
 What to add, where, what existing pattern to follow.
 Not a full spec — enough to start in the right direction.]

==========================
STANDING RULES
==========================
R1  Never include tests/__init__.py
R2  mypy always per-package — never: mypy packages/
      uv run mypy --package aevum.X
R3  Before any commit: git diff --cached --name-only | grep verify_ → abort if found
R4  JwksCache.invalidate() must clear both _fetched_at AND _keys
R5  CLI tests strip ANSI: re.sub(r"\x1b\[[0-9;]*[mGKH]", "", text)
R6  Quote pip specifiers: pip install "pkg>=1.0"
R7  No __init__.py in src/aevum/ or src/aevum/store/
R8  Build backend: hatchling only
R9  All packages at same version — bump all

==========================
ACCEPTANCE CRITERIA
==========================
For S: all must pass before committing.
For M/L: mark which phase each criterion applies to.

□ The new capability works as described in the implementation brief     [phase: ]
□ Tests cover the new code — follow existing test patterns              [phase: ]
□ mypy --package [affected] is clean                                    [phase: ]
□ ruff check and ruff format --check pass                               [phase: ]
□ Full suite still passing: uv run pytest packages/ --tb=short -q | tail -3  [phase: ]
□ Conformance suite still 9/9: uv run pytest packages/aevum-conformance/ -q | tail -3  [phase: ]
□ mkdocs build --strict passes — 0 errors, 0 warnings                  [final phase]
□ API reference updated for any new public class or function            [final phase]
□ CHANGELOG.md updated under [Unreleased]                               [final phase]
□ Getting-started guide still accurate                                   [final phase]

==========================
CHECKPOINTS  (M and L only)
==========================
After completing each phase, run:

  uv run pytest packages/ --tb=short -q 2>&1 | tail -3
  for pkg in [affected packages]; do uv run mypy --package $pkg 2>&1 | tail -2; done
  uv run ruff check packages/ 2>&1 | tail -3

If any check fails: fix before continuing to the next phase.
Do not let failures accumulate across phases.

==========================
CONTINUATION HANDOFF  (M and L — fill at end of each session)
==========================
If this is not the final phase, complete this block and return this to the maintainer.
paste it at the top of a new ENHANCEMENT.md session to continue.

─────────────────────────────────────────────────
ENHANCEMENT CONTINUATION — [WHAT] — Phase [N] of [Total]
─────────────────────────────────────────────────
Enhancement:    [what]
Completed:      Phase [N] — [one sentence describing what was built]
Commit:         [hash]
Tests:          [N passing]
Mypy:           CLEAN / [details]
Remaining:      Phase [N+1] — [description]
                Phase [N+2] — [description if applicable]
Known issues:   [anything Claude Code flagged, or "none"]
Next session:   Paste this block into ENHANCEMENT.md under CONTINUATION INPUT,
                then continue from Phase [N+1].
─────────────────────────────────────────────────

==========================
CONTINUATION INPUT  (paste prior handoff here to resume)
==========================
[ PASTE CONTINUATION HANDOFF HERE — or leave blank for a fresh start ]

==========================
COMMIT AND REPORT
==========================
Per-phase commit (M/L):
  git diff --cached --name-only | grep verify_ && echo "ABORT: verify script staged" || true
  git add -A
  git commit -m "feat([package]): [enhancement] — phase [N] of [total]

  [one sentence on what this phase delivers]
  Tests: [N] | Mypy: clean | Ruff: clean"

Final commit (all scopes):
  git add -A
  git commit -m "feat([package]): [one line description]

  [why — the driver from the brief]
  Tests: [N] | Conformance: 9/9 | Mypy: clean | Docs: mkdocs strict PASS"

Return to the maintainer:
  Phase completed:   [N of total, or "complete"]
  Commit:            [hash]
  Tests:             [N passing]
  Conformance:       [N/9]
  What was built:    [one paragraph]
  Docs updated:      [yes — what changed / no]
  Next session:      [continuation handoff block, or "none — complete"]
  Ready to release:  [yes / no — reason]

==========================
NOTE ON ONGOING MAINTENANCE
==========================
Once this enhancement is merged, it is automatically covered by the
monthly maintenance cycle — the full test suite, mypy, ruff, and
mkdocs strict build run on every push via ci.yml, and the monthly
Research session will track any protocol or compliance drift that
affects this new capability. No additional maintenance steps needed.
