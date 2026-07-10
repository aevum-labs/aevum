#!/usr/bin/env python3
"""Generate the Aevum release SBOM.

Provenance is not accuracy. `cyclonedx-py environment` inventories whatever
interpreter it is pointed at. Pointed at the release job's own environment it
describes hatchling and cyclonedx-bom, not Aevum. This script points it at a
throwaway, pip-less virtualenv containing only the wheels about to be published,
so the component set IS the shipped runtime closure.

Every axis the release might need to vary -- subject name, component type, spec
version, whether wheel digests are embedded -- is a flag. Changing the SBOM's
shape never requires editing YAML.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import tomllib

# Built by the release workflow but never published. Must never reach an SBOM.
PRIVATE: frozenset[str] = frozenset({"aevum-maintainer"})

SUBJECT_TEMPLATE = """\
[project]
name = "{name}"
version = "{version}"
description = "Aevum release distribution: published aevum-* packages and their runtime closure."
license = "Apache-2.0"
requires-python = ">=3.11"
dependencies = [
{deps}
]

[project.urls]
Homepage = "https://aevum.build"
Repository = "https://github.com/aevum-labs/aevum"
"""


def dist_name(artifact: pathlib.Path) -> str:
    """aevum_store_oxigraph-0.9.0-py3-none-any.whl -> aevum-store-oxigraph"""
    return artifact.name.split("-")[0].replace("_", "-")


def published_packages(packages_dir: pathlib.Path) -> list[str]:
    return sorted(
        p.name for p in packages_dir.iterdir() if p.is_dir() and p.name not in PRIVATE
    )


def core_version(packages_dir: pathlib.Path) -> str:
    data = tomllib.loads((packages_dir / "aevum-core" / "pyproject.toml").read_text())
    return str(data["project"]["version"])


def assert_no_private_artifacts(dist: pathlib.Path) -> None:
    leaked = sorted(
        a.name
        for a in [*dist.glob("*.whl"), *dist.glob("*.tar.gz")]
        if dist_name(a) in PRIVATE
    )
    if leaked:
        raise SystemExit(
            f"refusing to build an SBOM: private artifacts still in {dist}: {leaked}"
        )


def make_venv(dist: pathlib.Path, workdir: pathlib.Path) -> pathlib.Path:
    venv = workdir / "sbomenv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    wheels = sorted(dist.glob("*.whl"))
    if not wheels:
        raise SystemExit(f"no wheels found in {dist}")
    # Every aevum-* wheel is named by explicit file path, so no aevum package can
    # be resolved from an index. Third-party runtime dependencies (typer, fastapi,
    # cryptography, ...) MUST come from PyPI -- do not add --no-index or --no-deps:
    # the runtime closure is exactly what this SBOM exists to describe.
    subprocess.run(
        [
            sys.executable, "-m", "pip",
            "--python", str(venv / "bin" / "python"),
            "install", "--no-cache-dir",
            *[str(w) for w in wheels],
        ],
        check=True,
    )
    return venv


def write_subject(path: pathlib.Path, name: str, version: str, pkgs: list[str]) -> None:
    deps = ",\n".join(f'  "{p}=={version}"' for p in pkgs)
    path.write_text(SUBJECT_TEMPLATE.format(name=name, version=version, deps=deps))


def embed_wheel_digests(sbom: dict, dist: pathlib.Path) -> int:
    """Anchor the SBOM to the exact files that will be published."""
    by_name = {dist_name(w): w for w in dist.glob("*.whl")}
    n = 0
    for component in sbom.get("components", []):
        wheel = by_name.get(component["name"])
        if wheel is None:
            continue
        component["hashes"] = [
            {"alg": "SHA-256", "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}
        ]
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dist", type=pathlib.Path, default=pathlib.Path("dist"))
    ap.add_argument("--packages", type=pathlib.Path, default=pathlib.Path("packages"))
    ap.add_argument("--output", type=pathlib.Path, required=True)
    ap.add_argument("--subject-name", default="aevum")
    ap.add_argument("--subject-group", default="aevum-labs")
    ap.add_argument(
        "--mc-type", default="application", choices=["application", "library", "firmware"]
    )
    ap.add_argument("--spec-version", default="1.6")
    ap.add_argument("--no-wheel-digests", action="store_true")
    args = ap.parse_args(argv)

    assert_no_private_artifacts(args.dist)
    version = core_version(args.packages)
    pkgs = published_packages(args.packages)

    with tempfile.TemporaryDirectory() as tmp:
        workdir = pathlib.Path(tmp)
        subject = workdir / "subject.toml"
        write_subject(subject, args.subject_name, version, pkgs)
        venv = make_venv(args.dist, workdir)
        raw = workdir / "raw.json"
        subprocess.run(
            [
                sys.executable, "-m", "cyclonedx_py", "environment", str(venv),
                "--pyproject", str(subject),
                "--mc-type", args.mc_type,
                "--sv", args.spec_version,
                "--output-reproducible",
                "--output-format", "JSON",
                "--output-file", str(raw),
            ],
            check=True,
        )
        sbom = json.loads(raw.read_text())

    # PEP 621 has no `group`, so cyclonedx-py cannot set it from --pyproject.
    # Required: "aevum" is an existing PyPI distribution owned by an unrelated
    # project. The subject of this SBOM must not be mistakable for that package.
    sbom.setdefault("metadata", {}).setdefault("component", {})["group"] = args.subject_group

    digested = 0 if args.no_wheel_digests else embed_wheel_digests(sbom, args.dist)
    args.output.write_text(json.dumps(sbom, indent=2, sort_keys=False) + "\n")

    print(
        f"wrote {args.output}: subject {args.subject_group}/{args.subject_name} {version} "
        f"({args.mc_type}), {len(pkgs)} published packages, "
        f"{len(sbom.get('components', []))} components, {digested} wheel digests"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
