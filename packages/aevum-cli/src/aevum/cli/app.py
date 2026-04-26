"""
Top-level typer app. Sub-commands registered here.
"""

from __future__ import annotations

import typer

from aevum.cli.commands import complication, conformance, server, store, version

app = typer.Typer(
    name="aevum",
    help="Aevum context kernel -- command-line interface.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

app.add_typer(server.app, name="server")
app.add_typer(store.app, name="store")
app.add_typer(complication.app, name="complication")
app.add_typer(conformance.app, name="conformance")
app.command(name="version")(version.version_command)
