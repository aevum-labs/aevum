# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Compliance pack generator.

Bundles compliance docs + SBOM into a signed, verifiable package.
Every generation is a governed Aevum operation with a sigchain entry.
"""
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

# Hardcoded SBOM filename — never derived from user input (CWE-22 prevention).
# The release workflow places the SBOM here before the compliance pack runs.
_SBOM_FILENAME: str = "sbom.json"

# Semver-like: optional leading v, three numeric components only.
_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+$")


def _safe_version(version: str) -> str:
    """Validate version is semver. Raises ValueError on invalid input."""
    if not _VERSION_RE.match(version):
        raise ValueError(f"version must be semver (e.g. 0.4.0 or v0.4.0), got: {version!r}")
    return version


def compliance_docs_dir() -> Path:
    """Return the canonical compliance docs directory relative to this file's repo root."""
    # packages/aevum-maintainer/src/aevum_maintainer/compliance_pack.py
    # → repo_root/docs/compliance/
    return Path(__file__).parent.parent.parent.parent.parent / "docs" / "compliance"


def generate_manifest(
    version: str,
    *,
    _docs_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Build a manifest of all compliance files with their SHA256 hashes.

    All file paths are derived from hardcoded constants or ``__file__`` — no
    path is accepted from caller-controlled or user-controlled input (CWE-22).

    ``_docs_dir`` is a keyword-only test-injection point. It is never passed
    by the server endpoint; production code always uses ``compliance_docs_dir()``.
    """
    # Derive the docs directory from __file__ (hardcoded) unless a test overrides it.
    safe_docs_dir = (_docs_dir or compliance_docs_dir()).resolve()
    files: dict[str, str] = {}
    for doc_name in COMPLIANCE_DOCS:
        # doc_name is from the hardcoded COMPLIANCE_DOCS list; resolve() + is_relative_to()
        # confirms the path stays within safe_docs_dir (defence in depth).
        doc_path = (safe_docs_dir / doc_name).resolve()
        if doc_path.is_relative_to(safe_docs_dir) and doc_path.is_file():
            files[doc_name] = hashlib.sha256(doc_path.read_bytes()).hexdigest()
    # SBOM: looked up by hardcoded filename in CWD, never derived from any parameter.
    sbom = Path(_SBOM_FILENAME)
    if sbom.is_file():
        files[_SBOM_FILENAME] = hashlib.sha256(sbom.read_bytes()).hexdigest()
    return {
        "version": version,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "generator": "aevum-maintainer/compliance_pack.py",
        "files": files,
    }


def build_pack_payload(version: str) -> dict[str, Any]:
    """
    Build the ingest payload for a compliance pack generation event.

    The payload is suitable for passing to engine.ingest() to create
    a governed, sigchain-backed record of the generation.
    """
    safe_ver = _safe_version(version)
    manifest = generate_manifest(safe_ver)
    return {
        "event": "compliance_pack_generated",
        "manifest": manifest,
    }


def manifest_to_json(manifest: dict[str, Any], *, indent: int = 2) -> str:
    """Serialize a manifest to canonical JSON."""
    return json.dumps(manifest, sort_keys=True, indent=indent)
