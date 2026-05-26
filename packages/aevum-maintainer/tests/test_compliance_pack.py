# SPDX-License-Identifier: Apache-2.0
"""Tests for the compliance pack generator."""
import json
from pathlib import Path

import pytest
from aevum_maintainer.compliance_pack import (
    _SBOM_FILENAME,
    COMPLIANCE_DOCS,
    _safe_version,
    generate_manifest,
    manifest_to_json,
)

# ---------------------------------------------------------------------------
# generate_manifest — docs hashing
# ---------------------------------------------------------------------------


def test_generate_manifest_structure() -> None:
    manifest = generate_manifest("0.4.0")
    assert manifest["version"] == "0.4.0"
    assert manifest["generator"] == "aevum-maintainer/compliance_pack.py"
    assert "generated_at" in manifest
    assert "files" in manifest


def test_generate_manifest_hashes_real_compliance_docs() -> None:
    """All five compliance docs created in Track A are present and hashed."""
    manifest = generate_manifest("0.4.0")
    for name in COMPLIANCE_DOCS:
        assert name in manifest["files"], f"Missing compliance doc: {name}"
    assert all(len(v) == 64 for v in manifest["files"].values())


def test_generate_manifest_skips_missing_docs(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    (docs_dir / "nist-ai-rmf.md").write_text("# NIST")

    manifest = generate_manifest("0.4.0", _docs_dir=docs_dir)

    assert "nist-ai-rmf.md" in manifest["files"]
    assert "hipaa.md" not in manifest["files"]


def test_generate_manifest_sha256_is_deterministic(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    (docs_dir / "nist-ai-rmf.md").write_text("stable content")

    m1 = generate_manifest("0.4.0", _docs_dir=docs_dir)
    m2 = generate_manifest("0.4.0", _docs_dir=docs_dir)

    assert m1["files"] == m2["files"]


# ---------------------------------------------------------------------------
# generate_manifest — SBOM hashing (hardcoded filename in CWD)
# ---------------------------------------------------------------------------


def test_generate_manifest_includes_sbom_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / _SBOM_FILENAME).write_text(json.dumps({"bomFormat": "CycloneDX"}))
    monkeypatch.chdir(tmp_path)

    manifest = generate_manifest("0.4.0")

    assert _SBOM_FILENAME in manifest["files"]
    assert len(manifest["files"][_SBOM_FILENAME]) == 64


def test_generate_manifest_omits_sbom_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    manifest = generate_manifest("0.4.0")

    assert _SBOM_FILENAME not in manifest["files"]


# ---------------------------------------------------------------------------
# _safe_version
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# manifest_to_json
# ---------------------------------------------------------------------------


def test_manifest_to_json_is_sorted(tmp_path: Path) -> None:
    docs_dir = tmp_path / "compliance"
    docs_dir.mkdir()
    (docs_dir / "nist-ai-rmf.md").write_text("x")
    (docs_dir / "hipaa.md").write_text("y")

    manifest = generate_manifest("0.4.0", _docs_dir=docs_dir)
    serialized = manifest_to_json(manifest)

    parsed = json.loads(serialized)
    assert parsed["version"] == manifest["version"]
    keys = list(parsed.keys())
    assert keys == sorted(keys), "manifest_to_json must produce sorted keys"
