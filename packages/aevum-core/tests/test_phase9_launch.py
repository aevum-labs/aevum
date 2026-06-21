# SPDX-License-Identifier: Apache-2.0
"""Launch readiness checks. Verifies repository structure for public release."""
import json
import subprocess
from pathlib import Path


class TestVersionConsistency:
    def _get_version(self, pkg_name: str) -> str | None:
        toml = Path(f"packages/{pkg_name}/pyproject.toml")
        if not toml.exists():
            return None
        for line in toml.read_text().splitlines():
            if line.strip().startswith("version ="):
                return line.split("=")[-1].strip().strip('"')
        return None

    def test_aevum_core_at_0_8_0(self) -> None:
        assert self._get_version("aevum-core") == "0.8.0"

    def test_aevum_cli_at_0_8_0(self) -> None:
        assert self._get_version("aevum-cli") == "0.8.0"

    def test_aevum_mcp_at_0_8_0(self) -> None:
        assert self._get_version("aevum-mcp") == "0.8.0"

    def test_aevum_agent_at_0_8_0(self) -> None:
        assert self._get_version("aevum-agent") == "0.8.0"

    def test_aevum_conformance_at_0_8_0(self) -> None:
        assert self._get_version("aevum-conformance") == "0.8.0"


class TestPyTypedMarkers:
    """Rule 62: py.typed must be present in all active packages."""

    def _has_py_typed(self, pkg_name: str) -> bool:
        src = Path(f"packages/{pkg_name}/src")
        if not src.exists():
            return False
        return bool(list(src.rglob("py.typed")))

    def test_aevum_core_has_py_typed(self) -> None:
        assert self._has_py_typed("aevum-core"), "aevum-core missing py.typed (Rule 62)"

    def test_aevum_cli_has_py_typed(self) -> None:
        assert self._has_py_typed("aevum-cli"), "aevum-cli missing py.typed (Rule 62)"

    def test_aevum_mcp_has_py_typed(self) -> None:
        assert self._has_py_typed("aevum-mcp"), "aevum-mcp missing py.typed (Rule 62)"

    def test_aevum_agent_has_py_typed(self) -> None:
        assert self._has_py_typed("aevum-agent"), "aevum-agent missing py.typed (Rule 62)"

    def test_aevum_conformance_has_py_typed(self) -> None:
        assert self._has_py_typed("aevum-conformance"), \
            "aevum-conformance missing py.typed (Rule 62)"


class TestDocumentation:
    def test_readme_exists(self) -> None:
        assert Path("README.md").exists()

    def test_readme_does_not_have_bare_pip_install_aevum(self) -> None:
        """Rule 18: pip install aevum (bare) leads to wrong package."""
        lines = Path("README.md").read_text().splitlines()
        for line in lines:
            if "pip install aevum" in line:
                after = line[line.index("pip install aevum") + len("pip install aevum"):]
                assert after.startswith("-"), (
                    f"README has bare 'pip install aevum' (PyPI name is taken): {line!r}"
                )

    def test_readme_mentions_apache_license(self) -> None:
        content = Path("README.md").read_text()
        assert "Apache" in content or "apache" in content.lower()

    def test_changelog_exists(self) -> None:
        assert Path("CHANGELOG.md").exists()

    def test_changelog_has_0_4_0(self) -> None:
        assert "0.4.0" in Path("CHANGELOG.md").read_text()

    def test_conformance_report_exists(self) -> None:
        assert Path("docs/conformance_report.txt").exists()

    def test_conformance_report_shows_pass(self) -> None:
        content = Path("docs/conformance_report.txt").read_text()
        assert "STATUS: PASS" in content, \
            "Conformance report does not show STATUS: PASS"

    def test_conformance_report_has_eleven_invariants(self) -> None:
        content = Path("docs/conformance_report.txt").read_text()
        for i in range(1, 12):
            assert f"INVARIANT{i:>3}" in content or f"INVARIANT {i}" in content, \
                f"Conformance report missing invariant {i}"

    def test_owasp_crosswalk_exists(self) -> None:
        assert Path("docs/owasp_crosswalk.md").exists()

    def test_owasp_crosswalk_has_all_codes(self) -> None:
        content = Path("docs/owasp_crosswalk.md").read_text()
        for i in range(1, 11):
            assert f"ASI{i:02d}" in content

    def test_sample_audit_pack_is_valid_json_ld(self) -> None:
        pack_path = Path("docs/sample_audit_pack.json")
        assert pack_path.exists()
        pack = json.loads(pack_path.read_text())
        assert "@context" in pack
        assert "@graph" in pack
        assert len(pack["@graph"]) >= 3


class TestWorkflowFiles:
    def test_ci_workflow_exists(self) -> None:
        assert Path(".github/workflows/ci.yml").exists()

    def test_release_workflow_trusted_publishing(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "id-token: write" in content
        assert "pypa/gh-action-pypi-publish" in content

    def test_scorecard_workflow_exists(self) -> None:
        assert Path(".github/workflows/scorecard.yml").exists()

    def test_dependabot_exists(self) -> None:
        assert Path(".github/dependabot.yml").exists()


class TestInstallStory:
    def test_extras_defined_in_aevum_core(self) -> None:
        content = Path("packages/aevum-core/pyproject.toml").read_text()
        for extra in ("server", "mcp", "a2a", "oxigraph", "postgres",
                      "langgraph", "crewai", "openai-agents", "all", "dev"):
            assert extra in content, f"Missing extra [{extra}]"

    def test_no_lgpl_in_any_source(self) -> None:
        """Rule 12: Apache-2.0 only."""
        # Split the search term to avoid this file matching itself.
        term = "LG" + "PL"
        result = subprocess.run(
            ["grep", "-r", term,
             "--include=*.py", "--include=*.toml",
             "--exclude=verify_*.py",
             "--exclude=test_phase9_launch.py",
             "--exclude-dir=.git", "--exclude-dir=.venv", "."],
            capture_output=True, text=True
        )
        assert result.stdout.strip() == "", \
            f"{term} found in source: {result.stdout.strip()[:200]}"
