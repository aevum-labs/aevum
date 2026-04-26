"""
aevum complication list/suspend/resume -- manage complications.
"""

from __future__ import annotations

from typing import Annotated

import typer

app = typer.Typer(help="Manage installed complications.")


@app.command("list")
def list_complications(
    graph: Annotated[str, typer.Option(help="Graph backend")] = "memory",
) -> None:
    """List all installed complications with state and health."""
    from aevum.core.engine import Engine
    engine = Engine()
    complications = engine.list_complications()
    if not complications:
        typer.echo("No complications installed.")
        return
    typer.echo(f"Installed complications ({len(complications)}):")
    for name, entry in complications.items():
        state = entry["state"]
        typer.echo(f"  {name}: {state}")


@app.command("suspend")
def suspend(
    name: Annotated[str, typer.Argument(help="Complication name to suspend")],
) -> None:
    """Suspend an ACTIVE complication."""
    from aevum.core.engine import Engine
    from aevum.core.exceptions import ComplicationError
    engine = Engine()
    try:
        engine.suspend_complication(name)
        typer.echo(f"Suspended: {name}")
    except ComplicationError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1) from e


@app.command("resume")
def resume(
    name: Annotated[str, typer.Argument(help="Complication name to resume")],
) -> None:
    """Resume a SUSPENDED complication."""
    from aevum.core.engine import Engine
    from aevum.core.exceptions import ComplicationError
    engine = Engine()
    try:
        engine.resume_complication(name)
        typer.echo(f"Resumed: {name}")
    except ComplicationError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1) from e
