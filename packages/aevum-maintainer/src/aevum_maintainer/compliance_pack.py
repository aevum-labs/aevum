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
from pathlib import Path
from typing import Any

COMPLIANCE_DOCS = [
    "nist-ai-rmf.md",
    "hipaa.md",
    "eu-ai-act.md",
    "soc2.md",
    "gdpr-article-17.md",
]


def generate_manifest(
    docs_dir: Path,
    sbom_path: Path,
    version: str,
) -> dict[str, Any]:
    """Build a manifest of all compliance files with their SHA256 hashes."""
    files: dict[str, str] = {}
    for doc_name in COMPLIANCE_DOCS:
        doc_path = docs_dir / doc_name
        if doc_path.exists():
            content = doc_path.read_bytes()
            files[doc_name] = hashlib.sha256(content).hexdigest()
    if sbom_path.exists():
        files["sbom.json"] = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
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
    docs_dir = compliance_docs_dir()
    resolved_sbom = sbom_path or Path(f"sbom-{version}.json")
    manifest = generate_manifest(docs_dir, resolved_sbom, version)
    return {
        "event": "compliance_pack_generated",
        "manifest": manifest,
    }


def manifest_to_json(manifest: dict[str, Any], *, indent: int = 2) -> str:
    """Serialize a manifest to canonical JSON."""
    return json.dumps(manifest, sort_keys=True, indent=indent)
