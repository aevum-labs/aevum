"""
aevum server start -- start the Aevum HTTP API server.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

import typer
import uvicorn

if TYPE_CHECKING:
    from aevum.core.engine import Engine

app = typer.Typer(help="Manage the Aevum HTTP API server.")


@app.command("start")
def start(
    host: Annotated[str, typer.Option(help="Bind host")] = "0.0.0.0",
    port: Annotated[int, typer.Option(help="Bind port")] = 8000,
    workers: Annotated[int, typer.Option(help="Number of uvicorn workers")] = 1,
    graph: Annotated[
        str,
        typer.Option(
            help="Graph backend. Options: memory | oxigraph:<path> | postgres:<dsn>"
        ),
    ] = "memory",
    api_key: Annotated[
        str | None,
        typer.Option(envvar="AEVUM_API_KEY", help="API key (overrides AEVUM_API_KEY env var)"),
    ] = None,
    reload: Annotated[bool, typer.Option(help="Enable auto-reload (dev only)")] = False,
) -> None:
    """Start the Aevum HTTP API server."""
    import os

    if api_key:
        os.environ["AEVUM_API_KEY"] = api_key

    engine = _build_engine(graph)

    from aevum.server.app import create_app
    from aevum.server.core.config import Settings

    settings_with_overrides = Settings(
        host=host,
        port=port,
    )
    app_instance = create_app(engine=engine, settings=settings_with_overrides)

    typer.echo(f"Starting Aevum server on {host}:{port} (graph={graph})")
    uvicorn.run(
        app_instance,
        host=host,
        port=port,
        workers=workers if not reload else 1,
        reload=reload,
    )


def _build_engine(graph: str) -> Engine:
    """Build an Engine from the --graph flag."""
    from aevum.core.engine import Engine

    if graph == "memory":
        typer.echo("Graph backend: in-memory (dev only -- data lost on restart)")
        return Engine()

    if graph.startswith("oxigraph:"):
        path = graph[len("oxigraph:"):]
        from aevum.store.oxigraph import OxigraphStore
        typer.echo(f"Graph backend: Oxigraph at {path}")
        return Engine(graph_store=OxigraphStore(path=path))

    if graph.startswith("postgres:"):
        dsn = graph[len("postgres:"):]
        try:
            import psycopg
            from aevum.store.postgres import PostgresStore
            from aevum.store.postgres.store import initialize_schema
            conn = psycopg.connect(dsn)
            initialize_schema(conn)
            typer.echo("Graph backend: PostgreSQL")
            return Engine(graph_store=PostgresStore(conn))
        except ImportError:
            typer.echo("Error: aevum-store-postgres is not installed.", err=True)
            raise typer.Exit(code=1) from None

    typer.echo(f"Unknown graph backend: {graph!r}", err=True)
    typer.echo("Options: memory | oxigraph:<path> | postgres:<dsn>", err=True)
    raise typer.Exit(code=1)
