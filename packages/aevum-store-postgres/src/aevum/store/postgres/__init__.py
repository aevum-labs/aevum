"""
aevum.store.postgres -- PostgreSQL backends for graph, consent, and ledger.

Usage:
    from aevum.store.postgres import PostgresStore, PostgresConsentLedger, PostgresLedger
    from aevum.store.postgres.ledger import initialize_ledger_schema
    import psycopg

    conn = psycopg.connect("postgresql://user:pass@host/dbname")
    initialize_schema(conn)           # graph + consent DDL
    initialize_ledger_schema(conn)    # ledger DDL

    store = PostgresStore(conn)
    consent = PostgresConsentLedger(conn)
    ledger = PostgresLedger(conn, sigchain)

    engine = Engine(
        graph_store=store,
        consent_ledger=consent,
        ledger=ledger,
    )
"""

from aevum.store.postgres.consent import PostgresConsentLedger
from aevum.store.postgres.ledger import PostgresLedger
from aevum.store.postgres.store import PostgresStore

__version__ = "0.1.0"

__all__ = ["PostgresStore", "PostgresConsentLedger", "PostgresLedger"]
