"""
Tests for PostgresStore — GraphStore Protocol conformance.

Fake-conn tests run without a real database (use the fake_store_parts fixture).
Integration tests (pg_store fixture) skip unless AEVUM_TEST_POSTGRES_DSN is set.
"""

from __future__ import annotations

from typing import Any

from aevum.core.protocols.graph_store import GraphStore

# ── Protocol conformance ──────────────────────────────────────────────────────

def test_satisfies_graphstore_protocol(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    assert isinstance(store, GraphStore)


# ── Unit tests (FakeConn) ─────────────────────────────────────────────────────

def test_store_and_get_entity(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    store.store_entity("e1", {"content": "hello", "type": "text"})
    result = store.get_entity("e1")
    assert result is not None
    assert result["content"] == "hello"
    assert result["type"] == "text"


def test_get_nonexistent_entity_returns_none(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    assert store.get_entity("no-such-entity") is None


def test_update_entity_replaces_data(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    store.store_entity("e1", {"content": "original"})
    store.store_entity("e1", {"content": "updated"})
    result = store.get_entity("e1")
    assert result is not None
    assert result["content"] == "updated"


def test_query_entities_returns_matching(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    store.store_entity("s1", {"content": "data1"})
    store.store_entity("s2", {"content": "data2"})
    results = store.query_entities(["s1", "s2"])
    assert "s1" in results
    assert "s2" in results
    assert results["s1"]["content"] == "data1"


def test_query_entities_absent_returns_empty(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    assert store.query_entities(["not-here"]) == {}


def test_query_entities_empty_list(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    assert store.query_entities([]) == {}


def test_classification_ceiling_barrier2(fake_store_parts: Any) -> None:
    """Barrier 2: entities above classification_max are excluded."""
    store, _, _ = fake_store_parts
    store.store_entity("public", {"content": "public"}, classification=0)
    store.store_entity("secret", {"content": "secret"}, classification=3)

    results = store.query_entities(["public", "secret"], classification_max=0)
    assert "public" in results
    assert "secret" not in results

    results = store.query_entities(["public", "secret"], classification_max=3)
    assert "public" in results
    assert "secret" in results


def test_get_entity_classification(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    store.store_entity("e1", {"x": 1}, classification=2)
    assert store.get_entity_classification("e1") == 2
    assert store.get_entity_classification("unknown") == 0


def test_entity_count(fake_store_parts: Any) -> None:
    store, _, _ = fake_store_parts
    assert store.entity_count() == 0
    store.store_entity("e1", {"x": 1})
    store.store_entity("e2", {"x": 2})
    assert store.entity_count() == 2


# ── Integration tests (real Postgres) ────────────────────────────────────────

def test_pg_store_entity_real(pg_store: Any) -> None:
    assert isinstance(pg_store, GraphStore)
    pg_store.store_entity("real-e1", {"value": "hello"})
    result = pg_store.get_entity("real-e1")
    assert result is not None
    assert result["value"] == "hello"


def test_pg_update_entity_real(pg_store: Any) -> None:
    pg_store.store_entity("upd1", {"v": "first"})
    pg_store.store_entity("upd1", {"v": "second"})
    assert pg_store.get_entity("upd1")["v"] == "second"


def test_pg_classification_ceiling_real(pg_store: Any) -> None:
    pg_store.store_entity("pub", {"x": 1}, classification=0)
    pg_store.store_entity("priv", {"x": 2}, classification=3)
    results = pg_store.query_entities(["pub", "priv"], classification_max=0)
    assert "pub" in results
    assert "priv" not in results
