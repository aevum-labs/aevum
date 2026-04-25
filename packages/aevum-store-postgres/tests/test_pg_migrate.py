"""
Tests for migrate_from_oxigraph — entity + consent migration.
"""

from __future__ import annotations

from typing import Any

from aevum.core.consent.ledger import ConsentLedger
from aevum.core.consent.models import ConsentGrant
from aevum.store.postgres.migrate import migrate_from_oxigraph


class _FakeOxigraphStore:
    """Minimal stand-in for OxigraphStore to test migrate logic."""

    def __init__(self, entities: dict) -> None:
        self._entities = entities  # {entity_id: {"data": ..., "classification": ...}}

    def sparql_select(self, query: str) -> list[dict]:
        return [{"s": f"urn:aevum:entity:{eid}"} for eid in self._entities]

    def get_entity(self, entity_id: str) -> dict | None:
        record = self._entities.get(entity_id)
        return record["data"] if record else None

    def get_entity_classification(self, entity_id: str) -> int:
        record = self._entities.get(entity_id)
        return record["classification"] if record else 0


def _consent_with_grant() -> ConsentLedger:
    ledger = ConsentLedger()
    ledger.add_grant(ConsentGrant(
        grant_id="migrate-g1",
        subject_id="s1",
        grantee_id="actor",
        operations=["ingest", "query"],
        purpose="migration-test",
        classification_max=1,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))
    return ledger


def test_migrate_entities(fake_store_parts: Any) -> None:
    source = _FakeOxigraphStore({
        "e1": {"data": {"name": "Alice"}, "classification": 0},
        "e2": {"data": {"name": "Bob"}, "classification": 1},
    })
    target_store, target_consent, _ = fake_store_parts

    stats = migrate_from_oxigraph(source_store=source, target_store=target_store)

    assert stats["entities"] == 2
    assert stats["grants"] == 0
    assert target_store.get_entity("e1") == {"name": "Alice"}
    assert target_store.get_entity("e2") == {"name": "Bob"}
    assert target_store.get_entity_classification("e1") == 0
    assert target_store.get_entity_classification("e2") == 1


def test_migrate_consent_grants(fake_store_parts: Any) -> None:
    source = _FakeOxigraphStore({})
    target_store, target_consent, _ = fake_store_parts

    stats = migrate_from_oxigraph(
        source_store=source,
        target_store=target_store,
        source_consent=_consent_with_grant(),
        target_consent=target_consent,
    )

    assert stats["grants"] == 1
    grants = target_consent.all_grants()
    assert len(grants) == 1
    assert grants[0].grant_id == "migrate-g1"


def test_migrate_empty_source(fake_store_parts: Any) -> None:
    target_store, _, _ = fake_store_parts
    stats = migrate_from_oxigraph(
        source_store=_FakeOxigraphStore({}), target_store=target_store
    )
    assert stats == {"entities": 0, "grants": 0}


def test_migrate_preserves_classification(fake_store_parts: Any) -> None:
    source = _FakeOxigraphStore({
        "conf": {"data": {"secret": True}, "classification": 2},
    })
    target_store, _, _ = fake_store_parts
    migrate_from_oxigraph(source_store=source, target_store=target_store)
    assert target_store.get_entity_classification("conf") == 2
