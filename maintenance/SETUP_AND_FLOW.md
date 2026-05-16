# Aevum Maintenance — Setup and Process Guide

---

## File Layout

```
aevum/
├── .github/
│   ├── dependabot.yml                ← auto-opens dep update PRs weekly
│   └── workflows/
│       ├── ci.yml                    ← ruff, mypy, pytest, mkdocs on every push
│       ├── monthly-maintenance.yml   ← pip-audit + dep scan, commits scan_results.md
│       ├── release.yml               ← OIDC Trusted Publishing on tag push
│       ├── claude.yml                ← @claude mentions on issues → Claude Code PR
│       └── auto-merge.yml            ← auto-merges Dependabot patch PRs that pass CI
│
├── maintenance/
│   ├── templates/
│   │   ├── RESEARCH.md               ← Claude (claude.ai) session template
│   │   ├── EXECUTION.md              ← Claude Code session template
│   │   └── ENHANCEMENT.md            ← Claude Code enhancement session template
│   ├── generated/                    ← gitignore this folder
│   ├── scan_results.md               ← auto-written by monthly-maintenance.yml
│   ├── enhancements.md               ← persistent enhancement backlog
│   └── last_state.json               ← auto-written by Claude Code at session end
│
└── scripts/
    └── maint_kickoff.py              ← generates pre-filled handoffs; reads scan_results.md
```

Add to `.gitignore`:
```
maintenance/generated/
```

---

## One-Time Setup  *(desktop, ~60 min)*

**1. Copy files into the repo** using the layout above.

**2. Create a Claude Project** at claude.ai named "Aevum Maintenance".
   Add to Project Knowledge: `maintenance/templates/RESEARCH.md`,
   current `pyproject.toml`, `CHANGELOG.md`, and a short architecture brief.
   *(Mobile apps can't create Projects — do this once on desktop.)*

**3. Enable the GitHub MCP connector** in your Claude account settings.
   Claude can then pull current files from the repo without uploading them.

**4. Configure PyPI Trusted Publishing** at pypi.org:
   Manage → Project → Settings → Publishing → Add publisher.
   Set repo `aevum-labs/aevum`, workflow `release.yml`, environment `pypi`.
   Add a `pypi` GitHub Environment with required-reviewer protection.

**5. Install the Claude Code GitHub App** from any Claude Code session:
   ```
   /install-github-app
   ```
   This wires up the `ANTHROPIC_API_KEY` secret and creates `claude.yml`.

**6. Seed `maintenance/last_state.json`** with current values and commit it.

**7. Seed `maintenance/enhancements.md`** (empty is fine) and commit it.

That's it. Everything else runs automatically from here.

---

## What Runs Without You

| Trigger | What happens |
|---------|-------------|
| Every push to any branch | CI: ruff, mypy, pytest, mkdocs strict |
| Every Monday | Dependabot: opens PRs for new dep versions |
| Dependabot patch PR + CI green | auto-merge.yml: merges it automatically |
| 1st of every month at 13:00 UTC | monthly-maintenance.yml: pip-audit + dep freshness → commits `scan_results.md` |
| `@claude` in a GitHub issue | claude.yml: Claude Code implements the fix, opens a PR |

Most months, **nothing manual is required** beyond reviewing the PR that Claude Code opens.

---

## Monthly Workflow  *(when something needs attention)*

The monthly-maintenance.yml runs automatically on the 1st.
Check the result from GitHub mobile — Actions → monthly-maintenance → latest run.

### Fast path  *(0 CVEs, nothing unusual — most months)*
Read the step summary: "0 CVEs found, N dep updates available."
If Dependabot already opened PRs for those updates and CI is green,
auto-merge handled them. You're done.

### Full path  *(CVE found, protocol change, or investigation needed)*

**Step 1 — Generate handoffs**  *(1 min)*
```bash
python scripts/maint_kickoff.py
```
This reads `scan_results.md` (already in the repo from the workflow) and
produces two pre-filled files in `maintenance/generated/YYYY_MM/`.
No copy-pasting the step summary — it's embedded automatically.

**Step 2 — Research session**  *(20–30 min, Claude mobile app)*
Open the "Aevum Maintenance" Claude Project.
Paste `RESEARCH_YYYY_MM.md`. Scan results are pre-filled.
Claude runs all research phases and produces the Research Report.
Copy the Research Report text.

**Step 3 — Execution session**  *(30–45 min, claude.ai/code)*
Paste the Research Report into the `RESEARCH FINDINGS` section of
`EXECUTION_YYYY_MM.md`.
Paste the document into a Claude Code session.
Claude Code runs all phases, opens a PR with fixes and doc updates,
and writes `maintenance/last_state.json` automatically.

**Step 4 — Review and merge**  *(5 min, GitHub mobile)*
Review the PR Claude Code opened.
Merge from GitHub mobile.

**Step 5 — Approve release if needed**  *(2 min, GitHub mobile)*
If Claude Code pushed a release tag:
GitHub → Actions → release → Approve deployment.
PyPI Trusted Publishing handles the publish — no API key needed.

That's the full path. `last_state.json` was written by Claude Code.
No manual state update required.

---

## Enhancement Workflow

Enhancements come from the Research Report's ENHANCEMENT PROPOSALS section.
They are not applied during the maintenance session — each gets its own session.

All proposals are tracked in `maintenance/enhancements.md` across months.
Claude Code updates this file during each execution session.

**When you're ready to implement a proposal:**

1. Move it to "Now" in `enhancements.md` (or note this in the execution session).
2. Fill in `ENHANCEMENT.md` with the What, Why, Package, Scope, and Phases.
3. Paste into a new Claude Code session.

| Scope | Sessions | Handoff pattern |
|-------|----------|----------------|
| S — Small | 1 | Commit + PR at end |
| M — Medium | 1–2 | Checkpoint after core; Continuation Handoff if needed |
| L — Large | 2+ | Phase-by-phase; Continuation Handoff between sessions |

Claude Code opens a PR for every enhancement. you review and merge.
Once merged, the monthly CI covers it automatically — no additional setup.

---

## Lightweight Fixes  *(from anywhere, at any time)*

For small fixes — broken doc link, typo, stale version number in docs:

1. Open the issue on GitHub mobile.
2. Comment: `@claude fix the broken link in docs/learn/barriers.md`
3. The `claude.yml` workflow fires, Claude Code opens a PR with the fix.
4. Review and merge from GitHub mobile.

No session setup, no templates, no kickoff script.

---

## Intentional Human-in-the-Loop

These steps stay manual — they're judgment calls, not mechanical work:

| Step | Why it's manual |
|------|----------------|
| PR review and merge | Final verification before code lands |
| PyPI deployment approval | Last gate before public release |
| Enhancement prioritization | NOW / SOON / BACKLOG is a product decision |
| Scope agreement for M/L enhancements | you sign off before Claude Code starts |

Everything else is automated or handled by Claude Code with a PR review.

---

## Quarterly Additions  *(months 1, 4, 7, 10)*

No extra steps — built into the EXECUTION template.
Claude Code detects the quarterly month and runs additional checks:
SBOM, clean install from PyPI, Python version compat (3.11/3.12/3.13),
OpenSSF Scorecard, license audit, and enhancement backlog reprioritization.

---

## At a Glance

```
Every push
    └── CI (ruff, mypy, pytest, mkdocs) — automatic

Every Monday
    └── Dependabot PRs — automatic
        └── Patch + CI green → auto-merged — automatic
        └── Minor/major → PR waits for your review

1st of month
    └── monthly-maintenance.yml runs → scan_results.md committed — automatic
        │
        ├── 0 CVEs, nothing flagged → done (~2 min)
    │                                 (last_state.json only updates when
    │                                  a Claude Code session actually runs)
        │
        └── Something flagged
                │
                ▼
            python scripts/maint_kickoff.py  (~1 min)
                │
                ▼
            Claude: RESEARCH session  (~20–30 min, mobile)
                │
                ▼
            Claude Code: EXECUTION session  (~30–45 min, claude.ai/code)
                │   writes last_state.json automatically
                │   opens PR automatically
                │
                ▼
            the maintainer: review PR + merge  (~5 min, GitHub mobile)
                │
                └── Release? → approve PyPI deployment  (~2 min, GitHub mobile)

Any time
    └── @claude in an issue → Claude Code PR  (~0 min from the maintainer)

When an enhancement is ready
    └── Claude Code: ENHANCEMENT session  (scope-dependent)
        └── Opens PR → you review and merge
```
