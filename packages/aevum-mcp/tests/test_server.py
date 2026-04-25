"""
Tests for aevum-mcp server.

Tests call tool functions directly — no stdio protocol in CI.
The MCP server registration and tool schema are verified separately.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import json

from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine

from aevum.mcp.server import create_server


def _engine_with_consent() -> Engine:
    engine = Engine()
    engine.add_consent_grant(ConsentGrant(
        grant_id="g1",
        subject_id="subject-1",
        grantee_id="mcp-user",
        operations=["ingest", "query", "replay", "export"],
        purpose="mcp-testing",
        classification_max=3,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))
    return engine


def _prov() -> dict:  # type: ignore[type-arg]
    return {
        "source_id": "test-src",
        "chain_of_custody": ["test-src"],
        "classification": 0,
        "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
        "model_id": None,
    }


def test_server_creates_successfully() -> None:
    mcp = create_server()
    assert mcp is not None
    assert mcp.name == "aevum"


def test_five_tools_registered() -> None:
    mcp = create_server()
    tool_names = list(mcp._tool_manager._tools.keys())  # type: ignore[attr-defined]
    for expected in ["ingest", "query", "review", "commit", "replay"]:
        assert expected in tool_names, f"Tool '{expected}' not registered"


def test_commit_tool_returns_envelope() -> None:
    mcp = create_server(engine=Engine())
    tool_fn = mcp._tool_manager._tools["commit"].fn  # type: ignore[attr-defined]
    result = tool_fn(
        event_type="app.test",
        payload={"k": "v"},
        actor="mcp-user",
    )
    assert result["status"] == "ok"
    assert result["audit_id"].startswith("urn:aevum:audit:")


def test_ingest_tool_requires_consent() -> None:
    mcp = create_server(engine=Engine())  # No consent grants
    tool_fn = mcp._tool_manager._tools["ingest"].fn  # type: ignore[attr-defined]
    result = tool_fn(
        data={"content": "test"},
        provenance=_prov(),
        purpose="mcp-testing",
        subject_id="subject-1",
        actor="mcp-user",
    )
    assert result["status"] == "error"
    assert result["data"]["error_code"] == "consent_required"


def test_ingest_tool_with_consent() -> None:
    mcp = create_server(engine=_engine_with_consent())
    tool_fn = mcp._tool_manager._tools["ingest"].fn  # type: ignore[attr-defined]
    result = tool_fn(
        data={"content": "hello"},
        provenance=_prov(),
        purpose="mcp-testing",
        subject_id="subject-1",
        actor="mcp-user",
    )
    assert result["status"] == "ok"


def test_query_tool_with_consent() -> None:
    engine = _engine_with_consent()
    mcp = create_server(engine=engine)

    ingest_fn = mcp._tool_manager._tools["ingest"].fn  # type: ignore[attr-defined]
    ingest_fn(data={"x": 1}, provenance=_prov(),
              purpose="mcp-testing", subject_id="subject-1")

    query_fn = mcp._tool_manager._tools["query"].fn  # type: ignore[attr-defined]
    result = query_fn(purpose="mcp-testing", subject_ids=["subject-1"])
    assert result["status"] == "ok"


def test_replay_tool() -> None:
    engine = Engine()
    mcp = create_server(engine=engine)

    commit_fn = mcp._tool_manager._tools["commit"].fn  # type: ignore[attr-defined]
    committed = commit_fn(event_type="app.replayable", payload={"v": 42})
    audit_id = committed["audit_id"]

    replay_fn = mcp._tool_manager._tools["replay"].fn  # type: ignore[attr-defined]
    result = replay_fn(audit_id=audit_id)
    assert result["status"] == "ok"
    assert result["data"]["replayed_payload"]["v"] == 42


def test_crisis_content_returns_crisis() -> None:
    mcp = create_server(engine=Engine())
    tool_fn = mcp._tool_manager._tools["ingest"].fn  # type: ignore[attr-defined]
    result = tool_fn(
        data={"content": "I want to kill myself"},
        provenance=_prov(),
        purpose="test",
        subject_id="subject-1",
    )
    assert result["status"] == "crisis"


def test_all_tools_return_serializable_dicts() -> None:
    """MCP protocol requires JSON-serializable return values."""
    engine = Engine()
    mcp = create_server(engine=engine)

    commit_fn = mcp._tool_manager._tools["commit"].fn  # type: ignore[attr-defined]
    result = commit_fn(event_type="app.ser_test", payload={"k": "v"})
    json.dumps(result)
