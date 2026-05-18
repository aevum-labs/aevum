"""Tests for the compliance pack generator."""
import json
from pathlib import Path

import pytest
from aevum_maintainer.compliance_pack import (
    COMPLIANCE_DOCS,
    _safe_version,
    generate_manifest,
    manifest_to_json,
)


def test_generate_manifest_includes_all_docs(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs" / "compliance"
    docs_dir.mkdir(parents=True)
    for name in COMPLIANCE_DOCS:
        (docs_dir / name).write_text(f"# {name}")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX"}))

    manifest = generate_manifest(docs_dir, sbom, version="0.4.0")

    assert manifest["version"] == "0.4.0"
    assert manifest["generator"] == "aevum-maintainer/compliance_pack.py"
    assert "generated_at" in manifest
    for name in COMPLIANCE_DOCS:
        assert name in manifest["files"], f"Missing: {name}"
    assert "sbom.json" in manifest["files"]
    assert all(len(v) == 64 for v in manifest["files"].values()), "SHA256 hex must be 64 chars"


def test_generate_manifest_skips_missing_docs(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    (docs_dir / "nist-ai-rmf.md").write_text("# NIST")
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")

    manifest = generate_manifest(docs_dir, sbom, version="0.4.0")

    assert "nist-ai-rmf.md" in manifest["files"]
    assert "hipaa.md" not in manifest["files"]


def test_generate_manifest_skips_missing_sbom(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    sbom = tmp_path / "nonexistent.json"

    manifest = generate_manifest(docs_dir, sbom, version="0.4.0")

    assert "sbom.json" not in manifest["files"]


def test_generate_manifest_sha256_is_deterministic(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    (docs_dir / "nist-ai-rmf.md").write_text("stable content")
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")

    m1 = generate_manifest(docs_dir, sbom, version="0.4.0")
    m2 = generate_manifest(docs_dir, sbom, version="0.4.0")

    assert m1["files"] == m2["files"]


def test_safe_version_accepts_valid_semver() -> None:
    assert _safe_version("0.4.0") == "0.4.0"
    assert _safe_version("v1.2.3") == "v1.2.3"
    assert _safe_version("10.20.30") == "10.20.30"


def test_safe_version_rejects_traversal_attempts() -> None:
    with pytest.raises(ValueError):
        _safe_version("../../etc/passwd")
    with pytest.raises(ValueError):
        _safe_version("1.0")
    with pytest.raises(ValueError):
        _safe_version("")
    with pytest.raises(ValueError):
        _safe_version("1.0.0.0")


def test_generate_manifest_ignores_non_json_sbom(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    sbom = tmp_path / "sbom.txt"  # wrong suffix — must be .json
    sbom.write_text("not json")

    manifest = generate_manifest(docs_dir, sbom, version="0.4.0")

    assert "sbom.json" not in manifest["files"]


def test_manifest_to_json_is_sorted(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    (docs_dir / "nist-ai-rmf.md").write_text("x")
    (docs_dir / "hipaa.md").write_text("y")
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")

    manifest = generate_manifest(docs_dir, sbom, version="0.4.0")
    serialized = manifest_to_json(manifest)

    parsed = json.loads(serialized)
    assert parsed["version"] == manifest["version"]
    keys = list(parsed.keys())
    assert keys == sorted(keys), "manifest_to_json must produce sorted keys"
