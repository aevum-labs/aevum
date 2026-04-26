"""
aevum version -- print installed package versions.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

import typer

_PACKAGES = [
    "aevum-core",
    "aevum-server",
    "aevum-sdk",
    "aevum-store-oxigraph",
    "aevum-store-postgres",
    "aevum-mcp",
    "aevum-oidc",
    "aevum-llm",
    "aevum-cli",
]


def version_command() -> None:
    """Print versions of all installed Aevum packages."""
    typer.echo("Aevum package versions:")
    for pkg in _PACKAGES:
        try:
            ver = version(pkg)
            typer.echo(f"  {pkg}: {ver}")
        except PackageNotFoundError:
            typer.echo(f"  {pkg}: not installed")
