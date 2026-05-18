# SPDX-License-Identifier: Apache-2.0
"""Tests for Track B: six read-only MCP tools."""
from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest
from aevum.core.engine import Engine
from aevum_maintainer.mcp_tools import (
    create_mcp_server,
    get_backlog_items,
    get_compliance_pack_status,
    get_pending_reviews,
    get_sigchain_summary,
    get_test_count,
    verify_sigchain_integrity,
)


@pytest.fixture
def engine() -> Engine:
    return Engine()


# ---------------------------------------------------------------------------
# get_sigchain_summary
# ---------------------------------------------------------------------------


def test_get_sigchain_summary_structure(engine: Engine) -> None:
    result = get_sigchain_summary(engine)
    assert "total_entries" in result
    assert "recent_n" in result
    assert "recent" in result
    assert isinstance(result["total_entries"], int)
    assert isinstance(result["recent"], list)


def test_get_sigchain_summary_n_parameter(engine: Engine) -> None:
    result = get_sigchain_summary(engine, n=5)
    assert result["recent_n"] <= 5


def test_get_sigchain_summary_counts_entries(engine: Engine) -> None:
    import datetime
    import uuid

    from aevum.core.consent.models import ConsentGrant

    # Add a consent grant so ingest works
    engine.add_consent_grant(ConsentGrant(
        grant_id=str(uuid.uuid4()),
        subject_id="test-subject",
        grantee_id="test-actor",
        operations=["ingest"],
        purpose="test purpose",
        classification_max=0,
        granted_at=datetime.datetime.now(datetime.UTC).isoformat(),
        expires_at="2099-12-31T00:00:00Z",
    ))
    before = get_sigchain_summary(engine)["total_entries"]
    engine.commit(event_type="test.event", payload={"x": 1}, actor="test")
    after = get_sigchain_summary(engine)["total_entries"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# get_pending_reviews
# ---------------------------------------------------------------------------


def test_get_pending_reviews_empty() -> None:
    result = get_pending_reviews({})
    assert result["open_count"] == 0
    assert result["reviews"] == []


def test_get_pending_reviews_with_entries() -> None:
    now = time.time()
    reviews: dict[str, Any] = {
        "review-1": {"action_description": "deploy v0.5", "review_requested_at": now - 60},
        "review-2": {"action_description": "merge PR", "review_requested_at": now - 10},
    }
    result = get_pending_reviews(reviews)
    assert result["open_count"] == 2
    assert len(result["reviews"]) == 2
    # Each entry has review_id and age_seconds
    ids = {r["review_id"] for r in result["reviews"]}
    assert "review-1" in ids and "review-2" in ids
    for r in result["reviews"]:
        assert r["age_seconds"] >= 0


# ---------------------------------------------------------------------------
# get_compliance_pack_status
# ---------------------------------------------------------------------------


def test_get_compliance_pack_status_structure() -> None:
    result = get_compliance_pack_status()
    assert "docs" in result
    assert "docs_dir" in result
    assert isinstance(result["docs"], dict)


def test_get_compliance_pack_status_has_expected_docs() -> None:
    from aevum_maintainer.compliance_pack import COMPLIANCE_DOCS

    result = get_compliance_pack_status()
    for doc in COMPLIANCE_DOCS:
        assert doc in result["docs"], f"Missing doc in status: {doc}"


def test_get_compliance_pack_status_marks_existing_docs() -> None:
    result = get_compliance_pack_status()
    # nist-ai-rmf.md should exist in the real repo
    docs = result["docs"]
    # At least one doc should exist
    assert any(v.get("exists") for v in docs.values())


# ---------------------------------------------------------------------------
# get_test_count
# ---------------------------------------------------------------------------


def test_get_test_count_structure() -> None:
    result = get_test_count()
    # Either returns real data or reports file-not-found gracefully
    assert "test_count" in result
    assert "last_run_date" in result


def test_get_test_count_from_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test against a controlled last_state.json."""
    state_data = {"version": "0.4.0", "test_count": 902, "last_run_date": "2026-05-15"}
    # Patch the parents[4] resolution by patching get_test_count to use tmp_path

    import aevum_maintainer.mcp_tools as mcp_mod

    orig_path = mcp_mod.pathlib.Path

    class _FakePath:
        """Minimal shim that intercepts parents[4] in get_test_count."""
        def __init__(self, *args: Any) -> None:
            self._p = orig_path(*args)

        def __truediv__(self, other: str) -> Any:
            return self._p / other

        @property
        def parents(self) -> Any:
            class _FakeParents:
                def __getitem__(self, idx: int) -> Any:
                    if idx == 4:
                        return tmp_path
                    return orig_path(__file__).parents[idx]
            return _FakeParents()

    (tmp_path / "maintenance").mkdir()
    (tmp_path / "maintenance" / "last_state.json").write_text(json.dumps(state_data))

    monkeypatch.setattr(mcp_mod, "pathlib", type("M", (), {"Path": _FakePath})())
    result = get_test_count()
    assert result["test_count"] == 902
    assert result["last_run_date"] == "2026-05-15"


# ---------------------------------------------------------------------------
# get_backlog_items
# ---------------------------------------------------------------------------


def test_get_backlog_items_structure() -> None:
    result = get_backlog_items()
    assert "Now" in result
    assert "Soon" in result
    assert "Backlog" in result


def test_get_backlog_items_from_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    content = """# Aevum Enhancement Backlog

## Now  *(approved, next session)*

### Phase 5 demo page

## Soon  *(next 1–2 months)*

### A2A task issuance

## Backlog  *(good ideas, not yet prioritized)*

### SBOM filename gap
"""

    import aevum_maintainer.mcp_tools as mcp_mod

    orig_path = mcp_mod.pathlib.Path

    class _FakePath:
        def __init__(self, *args: Any) -> None:
            self._p = orig_path(*args)

        def __truediv__(self, other: str) -> Any:
            return self._p / other

        @property
        def parents(self) -> Any:
            class _FakeParents:
                def __getitem__(self, idx: int) -> Any:
                    if idx == 4:
                        return tmp_path
                    return orig_path(__file__).parents[idx]
            return _FakeParents()

    (tmp_path / "maintenance").mkdir()
    (tmp_path / "maintenance" / "enhancements.md").write_text(content)

    monkeypatch.setattr(mcp_mod, "pathlib", type("M", (), {"Path": _FakePath})())
    result = get_backlog_items()
    assert "Phase 5 demo page" in result["Now"]
    assert "A2A task issuance" in result["Soon"]
    assert "SBOM filename gap" in result["Backlog"]


# ---------------------------------------------------------------------------
# verify_sigchain_integrity
# ---------------------------------------------------------------------------


def test_verify_sigchain_integrity_fresh_engine(engine: Engine) -> None:
    result = verify_sigchain_integrity(engine)
    assert result["integrity_ok"] is True
    assert isinstance(result["chain_length"], int)
    assert result["chain_length"] >= 0


def test_verify_sigchain_integrity_after_commits(engine: Engine) -> None:
    engine.commit(event_type="test.a", payload={}, actor="test")
    engine.commit(event_type="test.b", payload={}, actor="test")
    result = verify_sigchain_integrity(engine)
    assert result["integrity_ok"] is True
    assert result["chain_length"] >= 2


# ---------------------------------------------------------------------------
# create_mcp_server — registration and importability
# ---------------------------------------------------------------------------


def test_mcp_tools_importable() -> None:
    """Acceptance: tools are importable as standalone functions."""
    assert callable(get_sigchain_summary)
    assert callable(verify_sigchain_integrity)
    assert callable(get_pending_reviews)
    assert callable(get_compliance_pack_status)
    assert callable(get_test_count)
    assert callable(get_backlog_items)


def test_create_mcp_server_returns_fastmcp(engine: Engine) -> None:
    from fastmcp import FastMCP

    mcp = create_mcp_server(engine=engine)
    assert isinstance(mcp, FastMCP)


async def test_create_mcp_server_has_six_tools(engine: Engine) -> None:
    mcp = create_mcp_server(engine=engine)
    tools = await mcp.list_tools()
    assert len(tools) == 6
    tool_names = {t.name for t in tools}
    assert "get_sigchain_summary_tool" in tool_names
    assert "verify_sigchain_integrity_tool" in tool_names
