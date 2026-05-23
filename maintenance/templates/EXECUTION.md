# Aevum — Execution Session Template

Paste this document (with the RESEARCH FINDINGS section filled in) into a
Claude Code session to run the monthly execution phase.

---

## RESEARCH FINDINGS

*(Paste the Research Report from the Claude research session here before
starting the execution session.)*

---

## Phase 0 — Pre-flight checklist

Before writing any code, verify the following. Check each item and record
the result. Do not proceed to Phase 1 until all items are resolved.

**S-16 check:** Read `regression-baseline-v0.6.0/README.md` before touching
any code. If a benchmark, conformance test, or compat entry regresses from the
baseline, treat it as a blocking issue requiring an ADR before proceeding.

- [ ] `git status` — working tree is clean
- [ ] CI is green on `main` before this session starts
- [ ] `python scripts/check_namespace.py` exits 0
- [ ] No `rekor.sigstore.dev` hardcoded in Python source
      (`grep -r "rekor.sigstore.dev" packages/`)
- [ ] All packages in `packages/*/pyproject.toml` exist on PyPI:

  ```bash
  for pkg in packages/aevum-*/pyproject.toml; do
    name=$(grep '^name' "$pkg" | cut -d'"' -f2)
    curl -sf "https://pypi.org/pypi/$name/json" > /dev/null \
      || echo "NOT ON PYPI: $name"
  done
  ```

  Any `NOT ON PYPI` result must be resolved before tagging a release.
  See `docs/deployment/new-package.md`.

  *v0.6.0 example: aevum-agent, aevum-spiffe, aevum-otel were new packages
  that would have failed Trusted Publishing. The pre-flight check in
  `release.yml` catches this before any packages are published.*

- [ ] `maintenance/enhancements.md` is current (no stale NOW items)

---

## Phase 1 — Apply fixes from Research Report

Apply each fix identified in the Research Report. For each:

1. Make the change.
2. Run the relevant test (`uv run pytest`, `uv run ruff check`, `uv run mypy`).
3. Commit with a descriptive message.

---

## Phase 2 — Dependency updates (if flagged)

If the Research Report flagged dependency updates:

1. Apply the updates (`uv lock --upgrade-package <name>`).
2. Run CI checks (`uv run pytest`, `uv run ruff check`).
3. Commit.

---

## Phase 3 — Documentation updates

Update `CHANGELOG.md` and any affected docs pages. If this session introduces
a new package, update `docs/deployment/new-package.md` with any relevant notes.

---

## Phase 4 — Quarterly checks *(months 1, 4, 7, 10 only)*

- SBOM generation: `cyclonedx-py environment --output-format json`
- Clean install from PyPI (or dist/) for each public package
- Python version compat: 3.11, 3.12, 3.13
- OpenSSF Scorecard review
- License audit: `pip-licenses --format=markdown`
- Enhancement backlog reprioritisation

---

## Phase 5 — Wrap-up

1. Write `maintenance/last_state.json` with current state.
2. Open a PR with all commits from this session.
3. Fill in the Continuation Handoff block below and paste it as a PR comment.

---

## CONTINUATION HANDOFF

```
Session date:         [date]
Branch:               [branch]
Commit:               [hash]
Phases completed:     [list]
Blocking issues:      [if any — else: none]
Ready to merge:       [yes/no]
```
