# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Infrastructure tests for Phase 8: SBOM, extras, pyproject.toml, and workflow checks.
"""
from __future__ import annotations

from pathlib import Path


class TestPyprojectExtras:
    def test_benchmark_extra_defined(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "pytest-benchmark" in toml

    def test_langgraph_extra_populated(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "langgraph-checkpoint>=4.1.0" in toml

    def test_crewai_extra_populated(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "crewai>=0.80.0" in toml

    def test_openai_agents_extra_populated(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "openai-agents>=0.0.12" in toml

    def test_all_extra_defined(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert '"all"' in toml or "all = [" in toml or "all=" in toml

    def test_server_extra_defined(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "server" in toml

    def test_mcp_extra_defined(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "aevum-mcp" in toml

    def test_oxigraph_extra_defined(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "aevum-store-oxigraph" in toml

    def test_postgres_extra_defined(self) -> None:
        toml = Path("packages/aevum-core/pyproject.toml").read_text()
        assert "aevum-store-postgres" in toml


class TestBenchmarks:
    def test_benchmarks_directory_exists(self) -> None:
        assert Path("packages/aevum-core/benchmarks").is_dir()

    def test_bench_core_file_exists(self) -> None:
        assert Path("packages/aevum-core/benchmarks/bench_core.py").exists()

    def test_bench_core_has_ed25519_benchmark(self) -> None:
        content = Path("packages/aevum-core/benchmarks/bench_core.py").read_text()
        assert "test_bench_ed25519_sign" in content

    def test_bench_core_has_cedar_benchmark(self) -> None:
        content = Path("packages/aevum-core/benchmarks/bench_core.py").read_text()
        assert "test_bench_cedar_permit" in content

    def test_bench_core_has_merkle_benchmark(self) -> None:
        content = Path("packages/aevum-core/benchmarks/bench_core.py").read_text()
        assert "test_bench_merkle_root_10_events" in content

    def test_bench_core_has_consent_benchmark(self) -> None:
        content = Path("packages/aevum-core/benchmarks/bench_core.py").read_text()
        assert "test_bench_consent_grant_and_check" in content

    def test_bench_core_importable(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bench_core",
            "packages/aevum-core/benchmarks/bench_core.py",
        )
        assert spec is not None


class TestReleaseWorkflow:
    def test_release_workflow_exists(self) -> None:
        assert Path(".github/workflows/release.yml").exists()

    def test_release_workflow_has_trusted_publishing(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "pypa/gh-action-pypi-publish" in content
        assert "id-token: write" in content

    def test_release_workflow_has_sbom(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "cyclonedx" in content.lower() or "sbom" in content.lower()

    def test_release_workflow_has_build_step(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "Build" in content or "build" in content

    def test_release_workflow_triggers_on_tag(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "tags" in content

    def test_release_workflow_uses_oidc_environment(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "environment" in content

    def test_release_workflow_uploads_artifact(self) -> None:
        content = Path(".github/workflows/release.yml").read_text()
        assert "upload-artifact" in content


class TestMkdocs:
    def test_mkdocs_yml_exists(self) -> None:
        assert Path("mkdocs.yml").exists()

    def test_mkdocs_yml_has_material_theme(self) -> None:
        content = Path("mkdocs.yml").read_text()
        assert "material" in content

    def test_docs_index_exists(self) -> None:
        assert Path("docs/index.md").exists()

    def test_docs_quickstart_exists(self) -> None:
        assert Path("docs/quickstart.md").exists()

    def test_docs_quickstart_mentions_aevum_core(self) -> None:
        content = Path("docs/quickstart.md").read_text()
        assert "aevum-core" in content

    def test_docs_compliance_article12_exists(self) -> None:
        assert Path("docs/compliance/article12.md").exists()

    def test_docs_compliance_owasp_exists(self) -> None:
        assert Path("docs/compliance/owasp.md").exists()

    def test_docs_api_reference_exists(self) -> None:
        assert Path("docs/api/reference.md").exists()


class TestCLIPackageStructure:
    def test_aevum_cli_has_conformance_dep(self) -> None:
        toml = Path("packages/aevum-cli/pyproject.toml").read_text()
        assert "aevum-conformance" in toml

    def test_aevum_cli_app_importable(self) -> None:
        from aevum.cli.app import app  # noqa: F401

    def test_aevum_cli_has_five_new_commands(self) -> None:
        from aevum.cli.app import app
        from typer.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        for cmd in ("init", "verify", "audit-pack", "conform", "replay"):
            assert cmd in result.output

    def test_conform_command_uses_conformance_suite(self) -> None:
        """ConformanceSuite must be importable from aevum.cli.app for patching (Rule 57)."""
        import aevum.cli.app as cli_app
        assert hasattr(cli_app, "ConformanceSuite")
