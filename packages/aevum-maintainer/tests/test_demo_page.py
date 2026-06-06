# SPDX-License-Identifier: Apache-2.0
"""Tests for Phase 5 Track A: demo page, health endpoint, and MCP tool proxy."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# GET / — demo page
# ---------------------------------------------------------------------------


def test_demo_page_serves_html(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


def test_demo_page_contains_aevum(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Aevum" in resp.text


def test_demo_page_contains_governance_sections(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.text
    assert "integrity" in body.lower()
    assert "sigchain" in body.lower()
    assert "consent" in body.lower()
    assert "compliance" in body.lower()


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


def test_health_endpoint_ok(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    # Version is read from package metadata at runtime; must be a semver string.
    import re
    assert re.match(r"^\d+\.\d+\.\d+", data["version"]), (
        f"Expected semver version, got {data['version']!r}"
    )


# ---------------------------------------------------------------------------
# GET /v1/mcp/{tool_name} — MCP tool proxy
# ---------------------------------------------------------------------------


def test_mcp_tool_verify_sigchain_integrity(client: TestClient) -> None:
    resp = client.get("/v1/mcp/verify_sigchain_integrity")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "verify_sigchain_integrity"
    assert "integrity_ok" in data["result"]
    assert "chain_length" in data["result"]
    assert data["result"]["integrity_ok"] is True
    assert isinstance(data["result"]["chain_length"], int)


def test_mcp_tool_get_sigchain_summary(client: TestClient) -> None:
    resp = client.get("/v1/mcp/get_sigchain_summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "get_sigchain_summary"
    result = data["result"]
    assert "total_entries" in result
    assert "recent_n" in result
    assert "recent" in result
    assert isinstance(result["recent"], list)


def test_mcp_tool_get_pending_reviews(client: TestClient) -> None:
    resp = client.get("/v1/mcp/get_pending_reviews")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "get_pending_reviews"
    result = data["result"]
    assert "open_count" in result
    assert "reviews" in result
    assert result["open_count"] == 0


def test_mcp_tool_get_compliance_pack_status(client: TestClient) -> None:
    resp = client.get("/v1/mcp/get_compliance_pack_status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "get_compliance_pack_status"
    assert "docs" in data["result"]
    assert isinstance(data["result"]["docs"], dict)


def test_mcp_tool_get_test_count(client: TestClient) -> None:
    resp = client.get("/v1/mcp/get_test_count")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "get_test_count"
    assert "test_count" in data["result"]


def test_mcp_tool_get_backlog_items(client: TestClient) -> None:
    resp = client.get("/v1/mcp/get_backlog_items")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "get_backlog_items"
    result = data["result"]
    assert "Now" in result
    assert "Soon" in result
    assert "Backlog" in result


def test_mcp_tool_unknown_returns_404(client: TestClient) -> None:
    resp = client.get("/v1/mcp/delete_everything")
    assert resp.status_code == 404


def test_mcp_tool_write_tool_blocked(client: TestClient) -> None:
    resp = client.get("/v1/mcp/generate_compliance_pack")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------


def test_static_index_html_accessible(client: TestClient) -> None:
    resp = client.get("/static/index.html")
    assert resp.status_code == 200
    assert "Aevum" in resp.text
