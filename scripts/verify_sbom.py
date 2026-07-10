#!/usr/bin/env python3
"""Verify a release SBOM actually describes the Aevum release distribution.

Runs between SBOM generation and attestation. An attestation over a wrong SBOM is
an honest signature on a false statement; this is the gate that makes the contents
true. Digests are RECOMPUTED from dist/ rather than trusted from the document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tomllib

# Built by the release workflow but never published. Must not appear in the SBOM.
PRIVATE: frozenset[str] = frozenset({"aevum-maintainer"})

# Never a runtime dependency of any shipped wheel. Presence means the SBOM
# inventoried the build/publish environment instead of the shipped closure.
# NOTE: jsonschema is deliberately absent -- `mcp` requires it unconditionally,
# so it is a legitimate component of the runtime closure. Do not add it here.
FORBIDDEN: frozenset[str] = frozenset(
    {
        "hatchling",
        "build",
        "cyclonedx-bom",
        "cyclonedx-python-lib",
        "pip",
        "setuptools",
        "wheel",
    }
)


def dist_name(artifact: pathlib.Path) -> str:
    """aevum_store_oxigraph-0.9.0-py3-none-any.whl -> aevum-store-oxigraph"""
    return artifact.name.split("-")[0].replace("_", "-")


def _fail(errors: list[str], sbom: pathlib.Path) -> int:
    print(f"SBOM verification FAILED for {sbom}", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sbom", type=pathlib.Path)
    ap.add_argument("--dist", type=pathlib.Path, default=pathlib.Path("dist"))
    ap.add_argument("--packages", type=pathlib.Path, default=pathlib.Path("packages"))
    ap.add_argument("--subject-name", default="aevum")
    ap.add_argument("--subject-group", default="aevum-labs")
    ap.add_argument("--skip-digests", action="store_true")
    args = ap.parse_args(argv)

    doc = json.loads(args.sbom.read_text())
    errors: list[str] = []

    expected_version = str(
        tomllib.loads((args.packages / "aevum-core" / "pyproject.toml").read_text())[
            "project"
        ]["version"]
    )
    expected = {p.name for p in args.packages.iterdir() if p.is_dir()} - set(PRIVATE)
    if not expected:
        return _fail(["no packages/ directories found -- run from the repo root"], args.sbom)

    # 1. The SBOM must name what it is an SBOM of.
    meta = doc.get("metadata", {})
    mc = meta.get("component")
    if not mc:
        errors.append("metadata.component is absent -- the SBOM does not name its subject")
    else:
        if mc.get("name") != args.subject_name:
            errors.append(
                f"metadata.component.name is {mc.get('name')!r}, expected {args.subject_name!r}"
            )
        # "aevum" is an existing PyPI distribution owned by an unrelated project.
        # The group namespaces our subject so it cannot be mistaken for it.
        if mc.get("group") != args.subject_group:
            errors.append(
                f"metadata.component.group is {mc.get('group')!r}, expected {args.subject_group!r}"
            )
        if mc.get("version") != expected_version:
            errors.append(
                f"metadata.component.version is {mc.get('version')!r}, "
                f"expected {expected_version!r}"
            )
        if mc.get("purl"):
            errors.append(
                f"metadata.component.purl is {mc.get('purl')!r} -- we do not own that name"
            )

    # 2. Reproducible output: no wall-clock timestamp in an attested artifact.
    if meta.get("timestamp"):
        errors.append("metadata.timestamp present -- generated without --output-reproducible")

    components = doc.get("components", [])
    names = {c["name"] for c in components}
    versions = {c["name"]: c.get("version") for c in components}

    # 3. Every published package is present, at the released version.
    missing = sorted(expected - names)
    if missing:
        errors.append(f"published packages missing from SBOM: {missing}")
    wrong = sorted(n for n in expected & names if versions.get(n) != expected_version)
    if wrong:
        errors.append(f"packages present at unexpected version: {wrong}")

    # 4. Private packages absent; build tooling absent.
    leaked = sorted(set(PRIVATE) & names)
    if leaked:
        errors.append(f"private packages present in SBOM: {leaked}")
    tooling = sorted(set(FORBIDDEN) & names)
    if tooling:
        errors.append(f"build tooling inventoried as shipped components: {tooling}")

    # 5. Digests are recomputed from the artifacts on disk, not trusted.
    if not args.skip_digests:
        on_disk = {
            dist_name(w): hashlib.sha256(w.read_bytes()).hexdigest()
            for w in args.dist.glob("*.whl")
        }
        for component in components:
            name = component["name"]
            if name not in expected:
                continue
            actual = on_disk.get(name)
            if actual is None:
                errors.append(f"{name} is in the SBOM but has no wheel in {args.dist}")
                continue
            declared = {h.get("alg"): h.get("content") for h in component.get("hashes", [])}
            if "SHA-256" not in declared:
                errors.append(f"{name} has no SHA-256 digest")
            elif declared["SHA-256"] != actual:
                errors.append(f"{name}: SBOM digest does not match the wheel in {args.dist}")

    if errors:
        return _fail(errors, args.sbom)

    print(
        f"SBOM OK: {args.sbom} -- subject {args.subject_group}/{args.subject_name} "
        f"{expected_version}, {len(expected)} published packages, "
        f"{len(components)} components, digests verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
