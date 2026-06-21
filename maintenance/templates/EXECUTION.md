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

**S-16 check:** Consult the regression baseline maintained in the `aevum-ops`
repo before touching any load-bearing code. If a benchmark, conformance test,
or compat entry regresses from the baseline, treat it as a blocking issue
requiring an ADR before proceeding.

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

## Phase 0.5 — Seat-Rotation Pre-flight (authoring-side, before the handoff ships)

**Rule:** every claim in a handoff is either (a) verified against source/primary
reference this session, or (b) explicitly tagged `UNVERIFIED — confirm before
use`. No claim ships as confident prose from memory. If you cannot name how a
seat below would attack the handoff, you have not occupied it.

Rotate through the seats the change touches. Not all apply to every pass — name
the ones that do, and record the check.

- [ ] **Implementer** — *"What does this field/function/symbol actually contain?"*
      Read it from source, do not infer from its name.
      › *Would have caught P2j:* `signer_key_id` is a UUID, not the pubkey hex.

- [ ] **Release engineer** — *"What breaks at the repo/monorepo level, not the
      file level?"* Namespace collisions, test-collection basenames, version
      bumps across all `packages/*`, PyPI presence, CI job scope.
      › *Would have caught the collision:* two `test_cli.py` basenames.

- [ ] **Adversary** — *"How would I forge a pass / defeat this control?"* For any
      verification, signing, or trust boundary: what does a malicious input
      supply, and does the check trust something the artifact carries about
      itself? (Trust anchors must be pinned out-of-band.)
      › *Did catch P2j by design:* embedded `mldsa65_pub` → circular verify.

- [ ] **Re-implementer** — *"Could a third party build a conformant component
      from the spec/handoff alone, in another language?"* Any gap or error in a
      load-bearing doc becomes their failed verification of our valid records.
      › *Spec-accuracy pass:* the fake `json.dumps` JCS would mismatch on non-ASCII.

- [ ] **Regulator / auditor's counsel** — *(compliance/regulatory artifacts)*
      Every citation verified against **primary source** (eCFR, OJ, NIST release),
      not a secondary blog. Claims are capability-framed, never compliance
      verdicts. Subsection numbers drift — pin them.
      › *P2L:* a vendor blog's "(f)(2)(ii)(A)" was wrong; codified is (f)(2)(i)(A).

- [ ] **Future maintainer** — *"In 12 months, does this still mean what it says?"*
      `UNVERIFIED` tags still gated, hedged dates still hedged, deferred items
      tracked in the plan (not in memory), no claim that silently went stale.

- [ ] **liboqs reality check** — *(any hybrid/PQC-touching pass)* Hybrid tests
      run **with liboqs built** (0.14.0 from source) or the gate is marked
      `pending CI`. A skipped test proves nothing.

**Output of Phase 0.5:** a one-line note per applicable seat in the handoff's
pre-flight section ("Implementer: read `signing.py:242` — confirmed 19 fields"),
so the executor and maintainer can see which seats were occupied and which
claims rest on verification vs. flag.

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
