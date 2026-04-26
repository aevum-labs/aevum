"""
aevum store migrate -- migrate between graph backends.
"""

from __future__ import annotations

from typing import Annotated

import typer

app = typer.Typer(help="Manage graph store backends.")


@app.command("migrate")
def migrate(
    from_backend: Annotated[str, typer.Option("--from", help="Source backend (oxigraph:<path>)")] = "",
    to_backend: Annotated[str, typer.Option("--to", help="Target backend (postgres:<dsn>)")] = "",
) -> None:
    """Migrate graph data between backends."""
    if not from_backend or not to_backend:
        typer.echo("Both --from and --to are required.", err=True)
        raise typer.Exit(code=1)

    if not from_backend.startswith("oxigraph:"):
        typer.echo(f"Unsupported source backend: {from_backend!r}", err=True)
        typer.echo("Currently supported source: oxigraph:<path>", err=True)
        raise typer.Exit(code=1)

    if not to_backend.startswith("postgres:"):
        typer.echo(f"Unsupported target backend: {to_backend!r}", err=True)
        typer.echo("Currently supported target: postgres:<dsn>", err=True)
        raise typer.Exit(code=1)

    try:
        from aevum.store.postgres.store import migrate_from_oxigraph
    except ImportError:
        typer.echo("Error: aevum-store-postgres is not installed.", err=True)
        raise typer.Exit(code=1) from None

    oxigraph_path = from_backend[len("oxigraph:"):]
    postgres_dsn = to_backend[len("postgres:"):]

    typer.echo(f"Migrating: {oxigraph_path} -> PostgreSQL")
    try:
        import psycopg
        conn = psycopg.connect(postgres_dsn)
        migrated = migrate_from_oxigraph(oxigraph_path, conn)
        typer.echo(f"Migration complete: {migrated} entities transferred.")
    except Exception as e:
        typer.echo(f"Migration failed: {e}", err=True)
        raise typer.Exit(code=1) from e
