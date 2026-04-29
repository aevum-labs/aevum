"""
Integration test: Engine using OxigraphStore instead of InMemoryGraphStore.
Verifies the real backend works end-to-end with the kernel.
"""

from __future__ import annotations

from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

from aevum.store.oxigraph import OxigraphStore


def _engine() -> Engine:
    store = OxigraphStore()
    engine = Engine(graph_store=store)
    engine.add_consent_grant(ConsentGrant(
        grant_id="g1",
        subject_id="subject-1",
        grantee_id="actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="integration-test",
        classification_max=3,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))
    return engine


def _prov() -> dict:
    return {
        "source_id": "test-src",
        "chain_of_custody": ["test-src"],
        "classification": 0,
    }


def test_ingest_then_query_with_oxigraph() -> None:
    engine = _engine()
    ingest_result = engine.ingest(
        data={"content": "hello world", "type": "text"},
        provenance=_prov(),
        purpose="integration-test",
        subject_id="subject-1",
        actor="actor",
    )
    assert ingest_result.status == "ok"

    query_result = engine.query(
        purpose="integration-test",
        subject_ids=["subject-1"],
        actor="actor",
    )
    assert query_result.status == "ok"
    assert "subject-1" in query_result.data["results"]


def test_classification_ceiling_enforced_via_engine() -> None:
    """Barrier 2 still applies when using OxigraphStore."""
    engine = _engine()
    engine.ingest(
        data={"content": "public"},
        provenance={**_prov(), "classification": 0},
        purpose="integration-test",
        subject_id="subject-1",
        actor="actor",
    )
    # Query with classification_max=0 — should get results
    r = engine.query(
        purpose="integration-test",
        subject_ids=["subject-1"],
        actor="actor",
        classification_max=0,
    )
    assert r.status == "ok"


def test_sigchain_intact_with_oxigraph() -> None:
    """Sigchain still works regardless of graph backend."""
    engine = _engine()
    for i in range(5):
        engine.commit(event_type=f"app.event_{i}", payload={"i": i}, actor="actor")
    assert engine.verify_sigchain() is True


def test_demo_ten_lines() -> None:
    """
    A developer can ingest data and query it back using OxigraphStore in ~10 lines.
    """
    from aevum.core import Engine
    from aevum.core.consent.models import ConsentGrant

    from aevum.store.oxigraph import OxigraphStore

    store = OxigraphStore()
    engine = Engine(graph_store=store)
    engine.add_consent_grant(ConsentGrant(
        grant_id="demo-grant", subject_id="user-42", grantee_id="demo-actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="demo", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    ingest = engine.ingest(
        data={"name": "Alice", "role": "engineer"},
        provenance={"source_id": "hr-system", "chain_of_custody": ["hr-system"],
                    "classification": 0},
        purpose="demo", subject_id="user-42", actor="demo-actor",
    )
    assert ingest.status == "ok"

    result = engine.query(
        purpose="demo", subject_ids=["user-42"], actor="demo-actor"
    )
    assert result.status == "ok"
    assert "user-42" in result.data["results"]
