# aevum-maintainer

Maintenance tooling for Aevum releases: compliance pack generator and release utilities.

**Not intended for end-user installation.** This package is used by the Aevum maintainers
to generate and sign compliance packs on each release.

## Status: private, ops-only, excluded from publish

This package is never published to PyPI. `.github/workflows/release.yml`
removes its wheel/sdist from `dist/` before the publish step and skips it
in the PyPI-registration pre-flight check — confirmed present in both
places as of the HO-SESSION5-CLOSE / THIN pass. `pip-audit` reporting it as
"not found on PyPI" is expected, not a finding — `scripts/check-security.sh`
parses `pip-audit -f json` and fails only on a non-empty vulnerability list.

It also deliberately breaks the monorepo's flat `aevum.*` namespace
convention (CLAUDE.md): its import path is the top-level `aevum_maintainer`
package (`src/aevum_maintainer/`), not `aevum.maintainer` under the shared
`aevum` namespace package. This is intentional, not an oversight — it has
zero importers outside its own package and zero external consumers, so it
does not participate in the namespace contract the publishable packages
share.

**Why it has not been relocated under `aevum.*`:** moving it would be an
invasive rename touching its own internal imports, CI references, and the
release-exclusion rules above, for a package nothing else depends on.
Given a release is imminent, that cost isn't worth paying now.
**Flagged as an optional post-1.0 cleanup**, not a blocker for any current
release.
