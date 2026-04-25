"""
migrate_from_oxigraph — export Oxigraph data and import into PostgresStore.

Usage:
    from aevum.store.postgres.migrate import migrate_from_oxigraph
    stats = migrate_from_oxigraph(
        source_store=oxigraph_store,
        target_store=postgres_store,
        source_consent=in_memory_ledger,    # optional
        target_consent=postgres_consent,    # optional
    )
    print(stats)  # {"entities": 42, "grants": 5}

CLI (after installation):
    aevum-store-migrate --source-dsn "" --target-dsn "postgresql://..."
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aevum.store.postgres.consent import PostgresConsentLedger
    from aevum.store.postgres.store import PostgresStore


def migrate_from_oxigraph(
    source_store: Any,
    target_store: PostgresStore,
    source_consent: Any | None = None,
    target_consent: PostgresConsentLedger | None = None,
) -> dict[str, int]:
    """
    Copy all entities and consent grants from an OxigraphStore to PostgresStore.

    Args:
        source_store:   An OxigraphStore instance (must have sparql_select,
                        get_entity, get_entity_classification).
        target_store:   The destination PostgresStore.
        source_consent: Optional ConsentLedger to migrate grants from.
        target_consent: Optional PostgresConsentLedger to migrate grants into.

    Returns:
        dict with counts: {"entities": <n>, "grants": <n>}
    """
    entities_migrated = 0
    grants_migrated = 0

    # --- Migrate entities ---
    rows = source_store.sparql_select(
        "SELECT DISTINCT ?s WHERE { GRAPH <urn:aevum:knowledge> { ?s ?p ?o } }"
    )
    for row in rows:
        iri: str = row.get("s", "")
        if not iri:
            continue
        # Strip namespace prefix added by OxigraphStore._entity_node
        entity_id = iri[len("urn:aevum:entity:"):] if iri.startswith("urn:aevum:entity:") else iri

        data = source_store.get_entity(entity_id)
        if data is None:
            # Try with the full IRI (entity_id was stored as IRI)
            data = source_store.get_entity(iri)
        if data is None:
            continue

        classification = source_store.get_entity_classification(entity_id)
        target_store.store_entity(entity_id, data, classification)
        entities_migrated += 1

    # --- Migrate consent grants ---
    if source_consent is not None and target_consent is not None:
        for grant in source_consent.all_grants():
            target_consent.add_grant(grant)
            grants_migrated += 1

    return {"entities": entities_migrated, "grants": grants_migrated}


def main() -> None:
    """CLI entry point for aevum-store-migrate."""
    parser = argparse.ArgumentParser(
        description="Migrate Aevum data from Oxigraph to PostgreSQL"
    )
    parser.add_argument(
        "--source-path",
        default=None,
        help="Path to Oxigraph store directory (omit for in-memory — useful only for testing)",
    )
    parser.add_argument(
        "--target-dsn",
        required=True,
        help="PostgreSQL DSN (e.g. postgresql://user:pass@localhost/aevum)",
    )
    args = parser.parse_args()

    try:
        import psycopg
    except ImportError:
        print("psycopg is required: pip install psycopg[binary]", file=sys.stderr)
        sys.exit(1)

    try:
        from aevum.store.oxigraph import OxigraphStore
    except ImportError:
        print("aevum-store-oxigraph is required for migration", file=sys.stderr)
        sys.exit(1)

    from aevum.store.postgres import PostgresConsentLedger, PostgresStore
    from aevum.store.postgres.schema import initialize_schema

    source = OxigraphStore(args.source_path)
    conn = psycopg.connect(args.target_dsn, autocommit=True)
    initialize_schema(conn)

    import threading
    lock = threading.Lock()
    target = PostgresStore(conn, lock)
    target_consent = PostgresConsentLedger(conn, lock)

    stats = migrate_from_oxigraph(
        source_store=source,
        target_store=target,
        source_consent=None,
        target_consent=target_consent,
    )
    conn.close()
    print(f"Migration complete: {stats['entities']} entities, {stats['grants']} grants")


if __name__ == "__main__":
    main()
