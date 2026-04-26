"""
aevum conformance run -- run the conformance suite.
"""

from __future__ import annotations

import subprocess
from typing import Annotated

import typer

app = typer.Typer(help="Run the Aevum conformance suite.")


@app.command("run")
def run(
    impl: Annotated[
        str,
        typer.Option(help="Python import path to AevumProtocol implementation"),
    ] = "aevum.core.engine:Engine",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """
    Run the aevum-conformance suite against an implementation.

    Requires aevum-conformance to be installed separately:
        pip install aevum-conformance
    """
    try:
        import importlib
        importlib.import_module("conformance")
    except ImportError:
        typer.echo(
            "aevum-conformance is not installed. "
            "Install from: github.com/aevum-labs/aevum-conformance",
            err=True,
        )
        raise typer.Exit(code=1) from None

    args = ["python", "-m", "pytest", "conformance/"]
    if verbose:
        args.append("-v")

    typer.echo(f"Running conformance suite against: {impl}")
    result = subprocess.run(args)
    raise typer.Exit(code=result.returncode)
