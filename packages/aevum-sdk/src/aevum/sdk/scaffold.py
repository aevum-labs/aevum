"""
Scaffold a new complication project.
Called by: aevum new <name>
"""

from __future__ import annotations

from pathlib import Path

_PYPROJECT = """[project]
name = "{name}"
version = "0.1.0"
description = "Aevum complication: {name}"
requires-python = ">=3.11"
license = {{ text = "Apache-2.0" }}
dependencies = ["aevum-sdk"]

[project.entry-points."aevum.complications"]
{slug} = "{module}.complication:{class_name}"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/{module}"]
"""

_COMPLICATION = """from aevum.sdk import Complication, Context


class {class_name}(Complication):
    name = "{slug}"
    version = "0.1.0"
    capabilities = ["{slug}"]

    async def run(self, ctx: Context, payload: dict) -> dict:
        # TODO: implement your complication logic here
        return {{"result": f"hello from {slug}, {{payload}}"}}
"""

_README = """# {name}

An Aevum complication.

## Development

    uv sync
    uv run pytest
    uv run aevum list

## Registration

This complication registers itself as `{slug}` via the
`aevum.complications` entry point group.
"""

_INIT = """\"\"\"
{name} — Aevum complication.
\"\"\"
"""


def scaffold(name: str, target_dir: Path | None = None) -> None:
    """
    Create a new complication project in ./<name>/.

    Args:
        name: Project name (kebab-case, e.g. "my-comp")
        target_dir: Where to create the project. Defaults to cwd/<name>.
    """
    slug = name.lower().replace(" ", "-").replace("_", "-")
    module = slug.replace("-", "_")
    class_name = "".join(part.title() for part in slug.split("-")) + "Complication"

    root = (target_dir or Path.cwd()) / slug
    if root.exists():
        print(f"Directory already exists: {root}")
        return

    src = root / "src" / module
    tests = root / "tests"

    src.mkdir(parents=True)
    tests.mkdir(parents=True)

    (root / "pyproject.toml").write_text(
        _PYPROJECT.format(name=name, slug=slug, module=module, class_name=class_name)
    )
    (root / "README.md").write_text(_README.format(name=name, slug=slug))
    (src / "__init__.py").write_text(_INIT.format(name=name))
    (src / "complication.py").write_text(
        _COMPLICATION.format(class_name=class_name, slug=slug)
    )
    (tests / "test_complication.py").write_text(
        f"""import pytest
from {module}.complication import {class_name}
from aevum.sdk import Context


@pytest.mark.asyncio
async def test_run() -> None:
    comp = {class_name}()
    ctx = Context(subject_ids=["s1"], purpose="test", actor="test-actor")
    result = await comp.run(ctx, {{"who": "world"}})
    assert isinstance(result, dict)


def test_health() -> None:
    assert {class_name}().health() is True


def test_manifest() -> None:
    m = {class_name}().manifest()
    assert m["name"] == "{slug}"
    assert m["version"] == "0.1.0"
    assert "{slug}" in m["capabilities"]
"""
    )

    print(f"Created complication project: {root}")
    print(f"  cd {slug}")
    print("  uv sync")
    print("  uv run pytest")
    print("  uv run aevum list")
