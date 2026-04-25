"""Tests for the scaffold command."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


def test_scaffold_creates_directory(tmp_path: Path) -> None:
    from aevum.sdk.scaffold import scaffold
    scaffold("my-test-comp", target_dir=tmp_path)
    project = tmp_path / "my-test-comp"
    assert project.is_dir()


def test_scaffold_creates_pyproject(tmp_path: Path) -> None:
    from aevum.sdk.scaffold import scaffold
    scaffold("my-comp", target_dir=tmp_path)
    pyproject = tmp_path / "my-comp" / "pyproject.toml"
    assert pyproject.is_file()
    content = pyproject.read_text()
    assert "aevum.complications" in content
    assert "my-comp" in content


def test_scaffold_creates_complication_file(tmp_path: Path) -> None:
    from aevum.sdk.scaffold import scaffold
    scaffold("echo-comp", target_dir=tmp_path)
    comp_file = tmp_path / "echo-comp" / "src" / "echo_comp" / "complication.py"
    assert comp_file.is_file()
    content = comp_file.read_text()
    assert "EchoCompComplication" in content
    assert "async def run" in content


def test_scaffold_creates_test_file(tmp_path: Path) -> None:
    from aevum.sdk.scaffold import scaffold
    scaffold("test-thing", target_dir=tmp_path)
    test_file = tmp_path / "test-thing" / "tests" / "test_complication.py"
    assert test_file.is_file()
    content = test_file.read_text()
    assert "async def test_run" in content
    assert "test_health" in content
    assert "test_manifest" in content


def test_scaffold_does_not_overwrite(tmp_path: Path) -> None:
    from aevum.sdk.scaffold import scaffold
    scaffold("dupe", target_dir=tmp_path)
    # Second call should not raise, just print a message
    scaffold("dupe", target_dir=tmp_path)
    # Only one directory should exist
    assert (tmp_path / "dupe").is_dir()


def test_scaffold_kebab_to_snake_module(tmp_path: Path) -> None:
    from aevum.sdk.scaffold import scaffold
    scaffold("my-cool-comp", target_dir=tmp_path)
    module_dir = tmp_path / "my-cool-comp" / "src" / "my_cool_comp"
    assert module_dir.is_dir()


def test_main_cli_new(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """aevum new <n> creates a project."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["aevum", "new", "cli-test"])
    from aevum.sdk.__main__ import main
    main()
    assert (tmp_path / "cli-test").is_dir()
