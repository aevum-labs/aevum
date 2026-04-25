"""
aevum.store.postgres — PostgreSQL GraphStore + ConsentLedger backend.

Usage (shared connection):
    import psycopg
    import threading
    from aevum.store.postgres import PostgresStore, PostgresConsentLedger
    from aevum.store.postgres.schema import initialize_schema

    conn = psycopg.connect(dsn, autocommit=True)
    initialize_schema(conn)
    lock = threading.Lock()
    store = PostgresStore(conn, lock)
    consent = PostgresConsentLedger(conn, lock)
    engine = Engine(graph_store=store, consent_ledger=consent)
"""

from aevum.store.postgres.consent import PostgresConsentLedger
from aevum.store.postgres.store import PostgresStore

__version__ = "0.1.0"

__all__ = ["PostgresStore", "PostgresConsentLedger"]
