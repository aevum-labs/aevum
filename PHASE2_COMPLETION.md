# Phase 2 Completion — Compliance Pack

**Branch:** `claude/aevum-phase-2-compliance-hCIn0`  
**PR:** #98  
**Date:** 2026-05-18  
**Commits:** cc21549 → 1cc76f3 → 21b4f99  

---

## What was delivered

### Track A — Compliance mapping docs
Four new files written directly from source code (barriers.py, sigchain.py,
consent/models.py, Cedar policy files):

| File | Maps to |
|---|---|
| `docs/compliance/nist-ai-rmf.md` | GOVERN→Cedar, MAP→ConsentGrant, MEASURE→sigchain, MANAGE→barriers+review |
| `docs/compliance/hipaa.md` | §164.312(b) audit controls, §164.312(c)(2) integrity, §164.312(a)(2)(iv) encryption, deployer checklist |
| `docs/compliance/eu-ai-act.md` | Article 25(4) exemption, Recital 89 model card, Articles 12/13/14 for Annex III adopters |
| `docs/compliance/soc2.md` | CC6.1/CC6.2/CC7.2/CC8.1 mapping, auditor extraction guide |

`mkdocs.yml` updated: new **Compliance** section added before ADRs containing all five files
(the four above + existing `gdpr-article-17.md`). The GDPR file also remains in Learn for
discoverability — MkDocs allows the same file in multiple nav positions.

### Track B — SBOM wiring
Changes to `.github/workflows/release.yml`:
- SBOM filename: `sbom.json` → `sbom-${{ github.ref_name }}.json`
- New permission: `attestations: write`
- New step: `actions/attest-build-provenance@c074443f1aee8d4aeeae555aebba3282517141b2  # v2.2.3`
  (see **G14** below — SHA must be re-verified before the next real release)
- `cyclonedx-bom>=4.0` added to root dev-dependencies (CLI: `cyclonedx-py`, flag: `--output-format json`)

### Track C — Compliance pack generator
New package: `packages/aevum-maintainer/`

| File | Purpose |
|---|---|
| `src/aevum_maintainer/__init__.py` | Package root, version 0.4.0 |
| `src/aevum_maintainer/compliance_pack.py` | `generate_manifest()`, `build_pack_payload()`, `_safe_version()` |
| `src/aevum_maintainer/server.py` | FastAPI `create_app()`, `/v1/compliance-pack/generate` endpoint |
| `tests/test_compliance_pack.py` | 9 tests covering manifest generation, version validation, SBOM presence/absence |

---

## Final state

| Check | Result |
|---|---|
| Tests | **895 passing** (87 skipped, was 890 before Phase 2) |
| Conformance | **21/21** |
| Mypy | Clean (pre-existing cedarpy import-not-found in aevum.core is unchanged) |
| Ruff | Clean |
| CodeQL | 3 high alerts resolved by commit 21b4f99 — waiting on CI re-scan |
| PR #98 | Open — CodeQL re-scan pending |

---

## New permanent gotchas (add to future session briefs)

### G11 — CodeQL CWE-22: `resolve()` is NOT a sanitizer
CodeQL's path-injection query does not recognise `Path.resolve()`, `Path.is_relative_to()`,
or custom regex validators as sanitizers for path traversal. The only reliable fix is to
ensure **no function parameter that could originate from user input flows into a file-read
sink**. Specifically:
- Do not accept `Path` parameters in functions reachable from HTTP request handlers.
- Derive all file paths from hardcoded module-level constants or `__file__`.
- For test injection, use keyword-only parameters prefixed with `_` (convention: never
  passed by production/server code, so CodeQL's interprocedural analysis doesn't follow
  the taint).

### G12 — `aevum-maintainer` package
- Location: `packages/aevum-maintainer/`
- Import path: `aevum_maintainer` (underscore — **NOT** a namespace package)
- `__init__.py` **IS** required and present at `src/aevum_maintainer/__init__.py`
- `[tool.uv.sources] aevum-core = { workspace = true }` is required in its `pyproject.toml`
- mypy: `uv run mypy --package aevum_maintainer`
- Phase 3 brief says "aevum-maintainer phases 2–5" — this session was phase 1 (skeleton).
  Phases 2–5 are deferred.

### G13 — `cyclonedx-bom` CLI spelling and flags
- PyPI package: `cyclonedx-bom`
- CLI binary: `cyclonedx-py` (not `cyclonedx-bom`)
- Correct flag: `--output-format json` (NOT `--format json` — that flag does not exist in ≥4.0)
- Output flag: `--output-file <path>` (NOT `--output`)
- Generated schema: CycloneDX **1.6** in the current environment (not 1.4 as some docs show)
- Added to root dev-dependencies; also `pip install "cyclonedx-bom>=4.0"` in release.yml

### G14 — SHA for `actions/attest-build-provenance` MUST be re-verified
The SHA `c074443f1aee8d4aeeae555aebba3282517141b2` (v2.2.3) was sourced from a web search
during this session because `curl` had no outbound network access. **It has not been
verified against the live GitHub API.** Re-verify before any real tagged release:
```bash
curl -sf "https://api.github.com/repos/actions/attest-build-provenance/commits/v2" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['sha'])"
```
If the SHA differs, update `.github/workflows/release.yml` line with the new pin.

### G15 — `zizmor` is not installed in the workspace
`zizmor` is not in root dev-dependencies and was not available in the sandbox. The Track B
acceptance criterion (`zizmor .github/workflows/release.yml`) could not be run. Install
with `uv tool install zizmor` on a machine with network access and verify release.yml is
clean before the next release.

### G16 — SBOM filename split: release vs. compliance pack
These two things use different SBOM filenames intentionally:
- **Release workflow** (`release.yml`): produces `sbom-{version}.json` (versioned artifact,
  attached to the GitHub release and attested).
- **Compliance pack generator** (`compliance_pack.py`): looks for hardcoded `sbom.json` in
  the **current working directory** (`_SBOM_FILENAME = "sbom.json"`).

If you want the compliance pack to include the SBOM hash, you must copy or symlink
`sbom-{version}.json` → `sbom.json` before running `build_pack_payload()`. A CI step that
does this has not been written yet — it is deferred.

### G17 — `_docs_dir` in `generate_manifest` is test-only
The `_docs_dir` keyword-only parameter in `generate_manifest()` exists solely for pytest
injection (so tests can point at temporary directories with fixture docs). **Never pass
`_docs_dir` from any HTTP-request-handling code.** If you do, CodeQL will immediately
re-flag it as CWE-22. The underscore prefix is the convention; enforce it.

### G18 — `test_generate_manifest_hashes_real_compliance_docs` depends on Track A docs
The test calls `generate_manifest("0.4.0")` with no `_docs_dir`, so it resolves to the
real `docs/compliance/` directory in the repo. It asserts all five compliance docs are
present. If any doc is renamed or deleted, this test breaks. This is intentional — the
test verifies the docs exist at the expected path — but be aware when refactoring doc
structure.

### G19 — aevum-maintainer is NOT version-checked by the R9 version consistency script
The monthly maintenance EXECUTION.md script checks version consistency across 8 known
packages. `aevum-maintainer` is not in that list. Add it or bump it manually alongside
the others when releasing. Current version: `0.4.0`.

---

## What was deliberately NOT done

| Item | Reason |
|---|---|
| Manifest Ed25519 signing (`manifest.json.sig`) | Requires key infrastructure; deferred to aevum-maintainer phase 2 |
| aevum-maintainer phases 2–5 | Out of scope for Phase 2 per the brief |
| Hybrid ML-DSA signing | Explicitly deferred per brief |
| `zizmor` verification of release.yml | No network / tool not installed |
| Compliance pack CI integration step | Would need to wire `build_pack_payload()` into release.yml; not in Phase 2 scope |
| SBOM copy/symlink step (`sbom-{version}.json` → `sbom.json`) | Related to above; deferred |

---

## Things to watch on PR #98

1. **CodeQL re-scan**: The third commit (21b4f99) removes all `Path` parameters from
   `generate_manifest()`. Wait for CodeQL to complete; all 3 alerts should be gone.
2. **Test matrix (3.11/3.12/3.13)**: Were still running when the session ended. Should pass —
   no version-specific code was introduced.
3. **attest-build-provenance SHA** (G14): Verify before merging if you want the attestation
   step to be production-ready.

---

## Files changed in this session

```
.github/workflows/release.yml          # SBOM rename, attestation, attestations:write permission
mkdocs.yml                              # Compliance nav section added
pyproject.toml                          # cyclonedx-bom>=4.0 in dev-dependencies
uv.lock                                 # updated by uv add
docs/compliance/nist-ai-rmf.md          # new
docs/compliance/hipaa.md                # new
docs/compliance/eu-ai-act.md            # new
docs/compliance/soc2.md                 # new
packages/aevum-maintainer/              # new package
  pyproject.toml
  README.md
  src/aevum_maintainer/__init__.py
  src/aevum_maintainer/compliance_pack.py
  src/aevum_maintainer/server.py
  src/aevum_maintainer/py.typed
  tests/test_compliance_pack.py
```
