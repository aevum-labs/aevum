"""
DDL for the Aevum PostgreSQL schema.

Two tables:
  aevum_entities       — entity data + classification (GraphStore backend)
  aevum_consent_grants — consent grants as JSONB (ConsentLedger backend)

Call initialize_schema(conn) once after connecting.
"""

from __future__ import annotations

from typing import Any

_DDL = """\
CREATE TABLE IF NOT EXISTS aevum_entities (
    entity_id      TEXT        PRIMARY KEY,
    data           JSONB       NOT NULL,
    classification INT         NOT NULL DEFAULT 0,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aevum_consent_grants (
    grant_id   TEXT  PRIMARY KEY,
    grant_data JSONB NOT NULL
);
"""


def initialize_schema(conn: Any) -> None:
    """Create Aevum tables if they do not already exist."""
    with conn.cursor() as cur:
        cur.execute(_DDL)
