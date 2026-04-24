"""
Tests for OxigraphStore — GraphStore Protocol conformance.
All tests run against in-memory store (no disk I/O in CI).
"""

from __future__ import annotations

from aevum.core.protocols.graph_store import GraphStore

from aevum.store.oxigraph import OxigraphStore


def _store() -> OxigraphStore:
    return OxigraphStore()  # in-memory


def test_satisfies_graphstore_protocol() -> None:
    """OxigraphStore must satisfy the GraphStore Protocol at runtime."""
    assert isinstance(_store(), GraphStore)


def test_store_and_get_entity() -> None:
    s = _store()
    s.store_entity("e1", {"content": "hello", "type": "text"})
    result = s.get_entity("e1")
    assert result is not None
    assert result["content"] == "hello"
    assert result["type"] == "text"


def test_get_nonexistent_entity_returns_none() -> None:
    s = _store()
    assert s.get_entity("does-not-exist") is None


def test_update_entity_replaces_data() -> None:
    s = _store()
    s.store_entity("e1", {"content": "original"})
    s.store_entity("e1", {"content": "updated"})
    result = s.get_entity("e1")
    assert result is not None
    assert result["content"] == "updated"


def test_query_entities_returns_matching() -> None:
    s = _store()
    s.store_entity("s1", {"content": "data1"})
    s.store_entity("s2", {"content": "data2"})
    results = s.query_entities(["s1", "s2"])
    assert "s1" in results
    assert "s2" in results
    assert results["s1"]["content"] == "data1"


def test_query_entities_absent_returns_empty() -> None:
    s = _store()
    results = s.query_entities(["not-here"])
    assert results == {}


def test_classification_ceiling_barrier2() -> None:
    """Barrier 2: entities above classification_max are excluded."""
    s = _store()
    s.store_entity("public-data", {"content": "public"}, classification=0)
    s.store_entity("secret-data", {"content": "secret"}, classification=3)

    # classification_max=0: only public data returned
    results = s.query_entities(["public-data", "secret-data"], classification_max=0)
    assert "public-data" in results
    assert "secret-data" not in results

    # classification_max=3: both returned
    results = s.query_entities(["public-data", "secret-data"], classification_max=3)
    assert "public-data" in results
    assert "secret-data" in results


def test_classification_stored_and_retrieved() -> None:
    s = _store()
    s.store_entity("classified", {"content": "sensitive"}, classification=2)
    assert s.get_entity_classification("classified") == 2
    assert s.get_entity_classification("unknown") == 0


def test_entity_count() -> None:
    s = _store()
    assert s.entity_count() == 0
    s.store_entity("e1", {"x": 1})
    s.store_entity("e2", {"x": 2})
    assert s.entity_count() == 2


def test_integer_values_round_trip() -> None:
    s = _store()
    s.store_entity("e1", {"count": 42, "label": "test"})
    result = s.get_entity("e1")
    assert result is not None
    assert result["count"] == 42


def test_three_named_graphs_exist() -> None:
    """The three Named Graph URIs must be present after store init."""
    from aevum.store.oxigraph.store import GRAPH_CONSENT, GRAPH_KNOWLEDGE, GRAPH_PROVENANCE
    s = _store()
    graphs = {str(g) for g in s._store.named_graphs()}
    assert str(GRAPH_KNOWLEDGE) in graphs
    assert str(GRAPH_PROVENANCE) in graphs
    assert str(GRAPH_CONSENT) in graphs


def test_clear_does_not_affect_consent_graph() -> None:
    """clear_knowledge_graph must not touch urn:aevum:consent."""
    from aevum.store.oxigraph.store import GRAPH_CONSENT
    s = _store()
    s.store_entity("e1", {"content": "data"})
    s.clear_knowledge_graph()
    assert s.get_entity("e1") is None
    # Consent graph still exists
    graphs = {str(g) for g in s._store.named_graphs()}
    assert str(GRAPH_CONSENT) in graphs


def test_thread_safety() -> None:
    """Concurrent writes must not corrupt the store."""
    import threading
    s = _store()
    errors: list[str] = []

    def write(i: int) -> None:
        try:
            s.store_entity(f"entity-{i}", {"value": i})
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=write, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Thread safety errors: {errors}"
    assert s.entity_count() == 20
