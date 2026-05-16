AEVUM MONTHLY EXECUTION
========================
Role:     Claude Code — execute, test, fix, sync docs, release
Research: RESEARCH.md session supplies the findings below
Generated: {{GENERATED_TIMESTAMP}}

Principle: Claude researches and classifies. Claude Code executes and commits.
           the maintainer reviews gate reports and makes release decisions.
           Docs ship with every release — code without matching docs does not ship.
           Think smarter, not harder.

Enhancement proposals in the Research Report are NOT acted on here.
They go to the maintainer for review and are implemented via ENHANCEMENT.md sessions.

========================
STARTING STATE
========================
Month:      {{MONTH_YEAR}}
Version:    {{CURRENT_VERSION}}
Last tests: {{LAST_TEST_COUNT}} passing

========================
RESEARCH FINDINGS
========================
(Paste Research Report here before starting)

[ PASTE RESEARCH REPORT HERE ]

========================
STANDING RULES
========================
R1  Never include tests/__init__.py
R2  mypy always per-package — never: mypy packages/
      uv run mypy --package aevum.X  (for each: core, server, mcp, agent,
      store.oxigraph, store.postgres, cli)
R3  Before any commit: git diff --cached --name-only | grep verify_ → abort if found
R4  JwksCache.invalidate() must clear both _fetched_at AND _keys
R5  CLI tests strip ANSI: re.sub(r"\x1b\[[0-9;]*[mGKH]", "", text)
R6  Quote pip specifiers: pip install "pkg>=1.0"
R7  No __init__.py in src/aevum/ or src/aevum/store/
R8  Build backend: hatchling only
R9  All packages at same version — bump all or none

========================
PHASE 0 — SETUP
========================

REPO=$(git rev-parse --show-toplevel) && cd "$REPO"
git status --short   # uncommitted changes not from this session → stop and report
[ -f CLAUDE.md ] && cat CLAUDE.md
uv --version

========================
PHASE 1 — CI HEALTH CHECK
========================
GitHub Actions CI already runs ruff, mypy, pytest, and mkdocs on every push.
Trust it if green. Only re-run specific checks if CI is red or a finding requires it.

Check the most recent CI run on main:
  git log --oneline -3
  # Visit: https://github.com/aevum-labs/aevum/actions

If CI is green on main → proceed to Phase 2.
If CI is red → identify which job failed, run that check only, treat failure as HIGH.

Also check version consistency across all packages:

python3 -c "
from pathlib import Path
pkgs = ['aevum-core','aevum-server','aevum-mcp','aevum-agent',
        'aevum-store-oxigraph','aevum-store-postgres','aevum-cli','aevum-conformance']
vers = {}
for p in pkgs:
    t = Path(f'packages/{p}/pyproject.toml')
    if t.exists():
        for l in t.read_text().splitlines():
            if l.strip().startswith('version ='):
                vers[p] = l.split('=',1)[1].strip().strip('\"'); break
u = set(vers.values())
print('VERSION: PASS —', next(iter(u))) if len(u)==1 else [print('VERSION: FAIL'), [print(f'  {k}: {v}') for k,v in vers.items()]]
"

========================
PHASE 2 — TRIAGE
========================
Cross-reference Research Findings with Phase 1 results.

CRITICAL — fix this session, may need emergency release:
  CVE CVSS >= 7.0 in crypto chain or confirmed exploit path
  Conformance test failure (any of 9)
  mypy error in aevum-core or aevum-conformance
  Test count below {{LAST_TEST_COUNT}}
  Version consistency FAIL
  Getting-started example broken (doc CRITICAL from Research)

HIGH — fix this session if time allows:
  CVE CVSS 4.0–6.9 direct dep
  Test regression (non-conformance)
  mypy error in any other package
  ruff violation (check or format)
  CI red (failing job)
  mkdocs build --strict fails
  Public API changed with no matching doc update

MEDIUM — log in gate report, do not act:
  Everything else from Research flagged MEDIUM

LOW — log only

========================
PHASE 3 — FIX
========================
Apply CRITICAL first, then HIGH. Stop there. MEDIUM: do not touch.

For each fix:
  a. Apply the minimal change that resolves the finding.
  b. Run the most targeted tests for this fix.
  c. Run mypy for the affected package (R2).
  d. Run ruff check on the affected package.

For dep version bumps:
  Edit specifier in ALL relevant pyproject.toml files.
  uv lock
  uv run pytest packages/ --tb=short -q 2>&1 | tail -3

If any fix touches aevum-core or aevum-conformance:
  Run full suite + conformance before the next fix:
    uv run pytest packages/ --tb=short -q 2>&1 | tail -3
    uv run pytest packages/aevum-conformance/ -v --tb=short 2>&1 | tail -10

After ALL fixes — verify before moving to Phase 4:
  uv run pytest packages/ --tb=short -q 2>&1 | tail -3
  uv run pytest packages/aevum-conformance/ --tb=short -q 2>&1 | tail -3
  for pkg in aevum.core aevum.server aevum.mcp aevum.agent \
             aevum.store.oxigraph aevum.store.postgres aevum.cli; do
    uv run mypy --package $pkg 2>&1 | tail -2; done
  uv run ruff check packages/ 2>&1 | tail -3
  uv run ruff format --check packages/ 2>&1 | tail -3

Commit (only if changes were made):
  git diff --cached --name-only | grep verify_ && echo "ABORT: verify script staged" || true
  git add -A
  git commit -m "fix: {{MONTH_YEAR}} maintenance — [one line summary]

  [dep or issue]: [what changed and why]
  Tests: [N] | Conformance: 9/9 | Mypy: clean | Ruff: clean"

========================
PHASE 4 — DOC SYNC  (required before release — not optional)
========================
Apply all DOC FIXES from Research Findings, then verify the checklist.

□ Apply every item listed under DOC FIXES in Research Findings.
□ For every public API change made in Phase 3 → update the API reference page.
□ For every dep bump → update any installation or requirements docs that reference it.
□ CHANGELOG.md has a complete entry for the version being released or [Unreleased].
□ mkdocs build --strict passes (0 errors, 0 warnings):
    mkdocs build --strict 2>&1 | tail -5  ← must exit 0 before proceeding
□ Version numbers consistent across pyproject.toml, mkdocs.yml, README, PyPI:
    python3 -c "
    import re; from pathlib import Path
    v = [l.split('=',1)[1].strip().strip('\"')
         for l in Path('packages/aevum-core/pyproject.toml').read_text().splitlines()
         if l.strip().startswith('version =')][0]
    for f,p in [('mkdocs.yml',r'[0-9]+\.[0-9]+\.[0-9]+'),
                ('CHANGELOG.md',r'\[?v?([0-9]+\.[0-9]+\.[0-9]+)\]?')]:
        m = re.search(p, Path(f).read_text() if Path(f).exists() else '')
        print(f'{f}: {m.group() if m else \"NOT FOUND\"} (expected {v})')"

Commit doc changes:
  git add docs/ mkdocs.yml CHANGELOG.md README.md
  git commit -m "docs: sync for {{MONTH_YEAR}} maintenance

  [what was updated]
  mkdocs strict: PASS" 2>/dev/null || echo "No doc changes to commit"

========================
PHASE 5 — RELEASE + GATE REPORT
========================
Release a patch if ANY of: CRITICAL CVE patched / conformance fixed /
  test regression fixed / HIGH CVE patched.
Skip if: all findings MEDIUM or LOW and no code or doc changes.
Prerequisite: Phase 4 mkdocs build --strict must have passed.

--- IF RELEASING ---

Bump all packages to {{PATCH_VERSION}}:
python3 - <<'EOF'
import re; from pathlib import Path
OLD, NEW = "{{CURRENT_VERSION}}", "{{PATCH_VERSION}}"
pkgs = ["aevum-core","aevum-server","aevum-mcp","aevum-agent",
        "aevum-store-oxigraph","aevum-store-postgres","aevum-cli","aevum-conformance"]
for p in pkgs:
    t = Path(f"packages/{p}/pyproject.toml")
    if not t.exists(): continue
    c = t.read_text()
    u = re.sub(rf'^(version\s*=\s*"){re.escape(OLD)}"', f'\\g<1>{NEW}"', c, flags=re.MULTILINE)
    if u != c: t.write_text(u); print(f"Bumped {p}")
    else: print(f"WARNING: no match in {p}")
EOF

Add CHANGELOG entry:
  ## [{{PATCH_VERSION}}] — {{MONTH_YEAR}}
  ### Security
  - [CVE-ID] ([level]): [dep] → [fix version]. [One sentence impact.]
  ### Fixed / Documentation
  - [brief]

Final full check:
  uv run pytest packages/ --tb=short -q 2>&1 | tail -3
  mkdocs build --strict 2>&1 | tail -3

Tag and push (CI publishes to PyPI via OIDC Trusted Publishing):
Tag and push. Claude Code opens a PR rather than pushing directly to main:

  # Create branch
  git checkout -b maint/{{MONTH_YEAR_SLUG}}

  # Commit all changes (fixes + docs + version bump if releasing)
  git diff --cached --name-only | grep verify_ && echo "ABORT: verify script staged" || true
  git add -A
  git commit -m "chore: {{MONTH_YEAR}} maintenance

  [summary of what changed]
  Tests: [N] | Conformance: 9/9 | Mypy: clean | Docs: mkdocs strict PASS"

  # Tag if releasing (before PR so CI picks it up)
  git tag v{{PATCH_VERSION}}   # only if releasing

  # Push branch and open PR
  git push origin maint/{{MONTH_YEAR_SLUG}}
  gh pr create \
    --title "chore: monthly maintenance {{MONTH_YEAR}}" \
    --body "## {{MONTH_YEAR}} Maintenance

  **Tests:** [N passing] (prev: {{LAST_TEST_COUNT}})
  **Conformance:** [N/9]
  **Mypy:** CLEAN
  **Docs:** mkdocs strict PASS
  **Release:** [YES v{{PATCH_VERSION}} / NO]

  ### Changes
  [list what was fixed and what docs were updated]

  ### Deferred
  [MEDIUM items for next month — or: none]

  ### Enhancement Proposals
  [from Research Report — or: none this month]" \
    --base main
  # you review and merge from GitHub mobile.
  # If a tag was pushed, the release.yml workflow fires on merge.

  # Save state — run after PR is created (not after merge)
  python3 - <<'SAVEEOF'
  import json
  from datetime import datetime
  from pathlib import Path

  # These values come from the commands run above — not estimates
  VERSION    = "{{PATCH_VERSION}}"   # update to {{CURRENT_VERSION}} if not releasing
  TEST_COUNT = 0                      # replace with actual number from pytest output
  DEFERRED   = []                     # replace with MEDIUM items from triage

  state = {
      "version":       VERSION,
      "test_count":    TEST_COUNT,
      "last_run_date": datetime.now().strftime("%Y-%m-%d"),
      "deferred":      DEFERRED,
  }
  Path("maintenance").mkdir(exist_ok=True)
  Path("maintenance/last_state.json").write_text(
      json.dumps(state, indent=2) + "\n"
  )
  print("Saved maintenance/last_state.json")
  SAVEEOF

  git add maintenance/last_state.json
  git commit --amend --no-edit   # fold into the branch commit
  git push origin maint/{{MONTH_YEAR_SLUG}} --force-with-lease

--- GATE REPORT ---

================================================================
AEVUM GATE REPORT — {{MONTH_YEAR}}
================================================================
CI on main:         GREEN / RED (job: [name])
Version check:      PASS / FAIL
Tests:              [N passed]  (prev: {{LAST_TEST_COUNT}})
Conformance:        [N/9]
Mypy:               CLEAN / [errors — packages]
Ruff:               CLEAN / [violations]
Docs (strict):      PASS / FAIL
Version nums:       CONSISTENT / [issues]

Findings actioned:
  CRITICAL: [item + resolution — or: none]
  HIGH:     [item + resolution — or: none]
  Doc fixes: [what was updated — or: none]

Deferred (MEDIUM):  [list — or: none]

Enhancement proposals carried forward:
  [list from Research Report ENHANCEMENT PROPOSALS — or: none]

Released:   YES (v{{PATCH_VERSION}}) / NO — [reason]
Commit:     [hash — or: none]

Next month watch: [1-2 items]
================================================================
END GATE REPORT
================================================================
  version, test_count, last_run_date, deferred

========================
QUARTERLY ADDITIONS  (months 1, 4, 7, 10 only)
========================
Run these after the standard phases above.

□ SBOM — pip install "cyclonedx-bom>=4" && cyclonedx-py environment
          --output-format json --output-file /tmp/sbom.json
          python3 -c "import json; d=json.load(open('/tmp/sbom.json'));
          c=d.get('components',[]); nl=[x['name'] for x in c if not x.get('licenses')];
          print(f'{len(c)} components, {len(nl)} with no license declared'); [print(f'  {n}') for n in nl[:5]]"
          rm /tmp/sbom.json

□ Clean install — pip install "aevum-core=={{CURRENT_VERSION}}" in fresh venv:
          python3 -m venv /tmp/aevum_clean && \
          /tmp/aevum_clean/bin/pip install "aevum-core=={{CURRENT_VERSION}}" --quiet && \
          /tmp/aevum_clean/bin/python3 -c "from aevum.core import Engine; print('PASS')" && \
          rm -rf /tmp/aevum_clean

□ Python compat — run core tests under each supported version:
          for v in 3.11 3.12 3.13; do
            command -v python$v && uv run --python $v pytest packages/aevum-core/tests/ -q 2>&1 | tail -2 \
            || echo "python$v: not available — skipped"; done

□ OpenSSF Scorecard — check https://securityscorecards.dev/#github.com/aevum-labs/aevum
          Note score and any check below 7/10.

□ License audit — confirm no new GPL/LGPL in default install path:
          pip-licenses --from=mixed --format=markdown 2>/dev/null | grep -iE "GPL|AGPL" \
          | grep -v LGPL | head -10 || echo "No GPL in install path"

□ Roadmap review — Claude Code reads enhancement proposals backlog and asks:
          Are any BACKLOG items now SOON or NOW given what changed this quarter?
          Note any reprioritizations in the gate report.

Add to gate report for quarterly months:
  SBOM:           [N components / license gaps: N]
  Clean install:  PASS / FAIL
  Python compat:  3.11 [P/F] / 3.12 [P/F] / 3.13 [P/F]
  OpenSSF:        [score] / low checks: [list or none]
  License audit:  CLEAN / [issues]
  Roadmap:        [any reprioritized enhancements]
