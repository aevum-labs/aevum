"""
Tests for aevum-cli commands.
Uses typer's CliRunner -- no real server, no real graph backend.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

from typer.testing import CliRunner

from aevum.cli.app import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "aevum-core" in result.output
    assert "aevum-cli" in result.output


def test_version_shows_not_installed_for_missing() -> None:
    result = runner.invoke(app, ["version"])
    # Packages not in test env show "not installed"
    assert "not installed" in result.output or result.exit_code == 0


def test_server_start_help() -> None:
    result = runner.invoke(app, ["server", "start", "--help"])
    assert result.exit_code == 0
    assert "--host" in result.output
    assert "--port" in result.output
    assert "--graph" in result.output
    assert "--workers" in result.output


def test_store_migrate_help() -> None:
    result = runner.invoke(app, ["store", "migrate", "--help"])
    assert result.exit_code == 0
    assert "--from" in result.output
    assert "--to" in result.output


def test_complication_list_empty() -> None:
    result = runner.invoke(app, ["complication", "list"])
    assert result.exit_code == 0
    assert "No complications installed" in result.output


def test_complication_list_help() -> None:
    result = runner.invoke(app, ["complication", "list", "--help"])
    assert result.exit_code == 0


def test_complication_suspend_help() -> None:
    result = runner.invoke(app, ["complication", "suspend", "--help"])
    assert result.exit_code == 0


def test_complication_resume_help() -> None:
    result = runner.invoke(app, ["complication", "resume", "--help"])
    assert result.exit_code == 0


def test_conformance_run_help() -> None:
    result = runner.invoke(app, ["conformance", "run", "--help"])
    assert result.exit_code == 0
    assert "--impl" in result.output


def test_store_migrate_requires_both_flags() -> None:
    result = runner.invoke(app, ["store", "migrate"])
    assert result.exit_code != 0


def test_store_migrate_unsupported_source() -> None:
    result = runner.invoke(app, ["store", "migrate", "--from", "memory:", "--to", "postgres:dsn"])
    assert result.exit_code != 0
    assert "Unsupported source" in result.output


def test_top_level_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["version", "server", "store", "complication", "conformance"]:
        assert cmd in result.output
