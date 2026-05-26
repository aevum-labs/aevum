# SPDX-License-Identifier: Apache-2.0
"""
aevum store — manage graph store backends and receipt storage.
"""

from __future__ import annotations

from typing import Annotated

import typer

app = typer.Typer(help="Manage graph store backends and receipt storage.")


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
        from aevum.store.postgres.migrate import migrate_from_oxigraph
    except ImportError:
        typer.echo("Error: aevum-store-postgres is not installed.", err=True)
        raise typer.Exit(code=1) from None

    oxigraph_path = from_backend[len("oxigraph:"):]
    postgres_dsn = to_backend[len("postgres:"):]

    typer.echo(f"Migrating: {oxigraph_path} -> PostgreSQL")
    try:
        import psycopg
        conn = psycopg.connect(postgres_dsn)
        migrated = migrate_from_oxigraph(oxigraph_path, conn)  # type: ignore[arg-type]  # Phase 2: wire store construction
        typer.echo(f"Migration complete: {migrated} entities transferred.")
    except Exception as e:
        typer.echo(f"Migration failed: {e}", err=True)
        raise typer.Exit(code=1) from e


@app.command("migrate-receipts")
def migrate_receipts(
    oxigraph_path: Annotated[
        str,
        typer.Option("--oxigraph", help="Path to Oxigraph store directory"),
    ] = "",
) -> None:
    """
    Migrate receipt blobs from Oxigraph provenance graph to SQLite receipt store.

    Checks for receipt blobs stored as xsd:base64Binary literals in the Oxigraph
    provenance graph and moves them to the SQLite receipt store (AEVUM_RECEIPT_DB).

    This is a one-time idempotent migration. For new deployments (no receipts in
    Oxigraph), this is a no-op. Receipt blobs were never stored in Oxigraph in
    versions <= 0.6.0, so this command is a no-op for all current deployments.
    """
    try:
        from aevum.core.sqlite_store import SqliteReceiptStore
        store = SqliteReceiptStore.from_env()
    except RuntimeError as exc:
        typer.echo(f"Store error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    if not oxigraph_path:
        typer.echo("No receipts to migrate. SQLite store is current.")
        raise typer.Exit(code=0)

    try:
        from aevum.store.oxigraph.store import OxigraphStore
        graph_store = OxigraphStore(path=oxigraph_path)
    except ImportError:
        typer.echo("Error: aevum-store-oxigraph is not installed.", err=True)
        raise typer.Exit(code=1) from None

    # Query for any receipt blobs stored as literals in the provenance graph.
    # Receipt blobs were never stored in Oxigraph in v0.6.0 or earlier, so
    # this query returns zero rows for all current deployments.
    sparql = """
        SELECT ?h ?b WHERE {
            GRAPH <urn:aevum:provenance> {
                ?h <https://aevum.build/vocab/receiptBlob> ?b
            }
        }
    """
    rows = graph_store.sparql_select(sparql)

    if not rows:
        typer.echo("No receipts to migrate. SQLite store is current.")
        raise typer.Exit(code=0)

    import base64
    migrated = 0
    for row in rows:
        h = row.get("h", "")
        b_str = row.get("b", "")
        if not h or not b_str:
            continue
        try:
            blob = base64.b64decode(b_str)
            receipt_hash = h.split(":")[-1] if ":" in h else h
            store.put(receipt_hash=receipt_hash, blob=blob)
            migrated += 1
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"  Skipped {h}: {exc}", err=True)

    typer.echo(f"Migrated {migrated} receipts from Oxigraph to SQLite.")
