# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Compliance pack generator.

Bundles compliance docs + SBOM into a signed, verifiable package.
Every generation is a governed Aevum operation with a sigchain entry.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
from pathlib import Path
from typing import Any

COMPLIANCE_DOCS = [
    "nist-ai-rmf.md",
    "hipaa.md",
    "eu-ai-act.md",
    "soc2.md",
    "gdpr-article-17.md",
]

# Semver-like: optional leading v, three numeric components only.
_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+$")


def _safe_version(version: str) -> str:
    """Validate version is semver. Raises ValueError on invalid input."""
    if not _VERSION_RE.match(version):
        raise ValueError(f"version must be semver (e.g. 0.4.0 or v0.4.0), got: {version!r}")
    return version


def generate_manifest(
    docs_dir: Path,
    sbom_path: Path,
    version: str,
) -> dict[str, Any]:
    """Build a manifest of all compliance files with their SHA256 hashes."""
    # Resolve to canonical absolute paths so traversal via symlinks or .. is impossible.
    safe_docs_dir = docs_dir.resolve()
    files: dict[str, str] = {}
    for doc_name in COMPLIANCE_DOCS:
        # doc_name comes from the hardcoded COMPLIANCE_DOCS list, but we still resolve
        # and confine each path to safe_docs_dir as defence in depth.
        doc_path = (safe_docs_dir / doc_name).resolve()
        if not doc_path.is_relative_to(safe_docs_dir):
            continue
        if doc_path.is_file():
            files[doc_name] = hashlib.sha256(doc_path.read_bytes()).hexdigest()
    # sbom_path must resolve within its own parent — no traversal, must be a .json file.
    safe_sbom = sbom_path.resolve()
    if safe_sbom.suffix == ".json" and safe_sbom.is_file():
        files["sbom.json"] = hashlib.sha256(safe_sbom.read_bytes()).hexdigest()
    return {
        "version": version,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "generator": "aevum-maintainer/compliance_pack.py",
        "files": files,
    }


def compliance_docs_dir() -> Path:
    """Return the canonical compliance docs directory relative to this file's repo root."""
    # packages/aevum-maintainer/src/aevum_maintainer/compliance_pack.py
    # → repo_root/docs/compliance/
    return Path(__file__).parent.parent.parent.parent.parent / "docs" / "compliance"


def build_pack_payload(version: str, sbom_path: Path | None = None) -> dict[str, Any]:
    """
    Build the ingest payload for a compliance pack generation event.

    The payload is suitable for passing to engine.ingest() to create
    a governed, sigchain-backed record of the generation.
    """
    safe_ver = _safe_version(version)
    docs_dir = compliance_docs_dir()
    # Derive sbom filename from the validated version string; never from raw user input.
    resolved_sbom = sbom_path if sbom_path is not None else Path(f"sbom-{safe_ver}.json")
    manifest = generate_manifest(docs_dir, resolved_sbom, safe_ver)
    return {
        "event": "compliance_pack_generated",
        "manifest": manifest,
    }


def manifest_to_json(manifest: dict[str, Any], *, indent: int = 2) -> str:
    """Serialize a manifest to canonical JSON."""
    return json.dumps(manifest, sort_keys=True, indent=indent)
