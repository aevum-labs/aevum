# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Read-only MCP tools for aevum-maintainer research sessions.

Claude uses these six tools to query the sigchain and inspect system state
before proposing changes. All tools are read-only — no state is modified.
"""
from __future__ import annotations

import json
import pathlib
import time
from typing import Any

from aevum.core.engine import Engine
from fastmcp import FastMCP


def get_sigchain_summary(engine: Engine, n: int = 10) -> dict[str, Any]:
    """Return a summary of the most recent sigchain entries."""
    total = engine.ledger_count()
    entries = engine.get_ledger_entries()
    recent = entries[-n:] if len(entries) > n else entries
    return {"total_entries": total, "recent_n": len(recent), "recent": recent}


def get_pending_reviews(pending_reviews: dict[str, Any]) -> dict[str, Any]:
    """Return open review IDs and their age in seconds."""
    now = time.time()
    return {
        "open_count": len(pending_reviews),
        "reviews": [
            {"review_id": rid, "age_seconds": round(now - v["review_requested_at"], 1)}
            for rid, v in pending_reviews.items()
        ],
    }


def get_compliance_pack_status() -> dict[str, Any]:
    """Check which compliance docs exist and when they were last modified."""
    from aevum_maintainer.compliance_pack import COMPLIANCE_DOCS, compliance_docs_dir

    docs_dir = compliance_docs_dir()
    result: dict[str, Any] = {}
    for name in COMPLIANCE_DOCS:
        path = docs_dir / name
        if path.is_file():
            result[name] = {"exists": True, "last_modified": path.stat().st_mtime}
        else:
            result[name] = {"exists": False}
    return {"docs": result, "docs_dir": str(docs_dir)}


def get_test_count() -> dict[str, Any]:
    """Read current test count and last run date from maintenance/last_state.json."""
    repo_root = pathlib.Path(__file__).parents[4]
    state_file = repo_root / "maintenance" / "last_state.json"
    if not state_file.is_file():
        return {"test_count": None, "last_run_date": None, "error": "last_state.json not found"}
    data: dict[str, Any] = json.loads(state_file.read_text())
    return {
        "test_count": data.get("test_count"),
        "last_run_date": data.get("last_run_date"),
        "version": data.get("version"),
    }


def get_backlog_items() -> dict[str, Any]:
    """Read Now/Soon/Backlog items from maintenance/enhancements.md."""
    repo_root = pathlib.Path(__file__).parents[4]
    backlog_file = repo_root / "maintenance" / "enhancements.md"
    if not backlog_file.is_file():
        return {"error": "enhancements.md not found", "Now": [], "Soon": [], "Backlog": []}
    content = backlog_file.read_text()
    sections: dict[str, list[str]] = {"Now": [], "Soon": [], "Backlog": []}
    current_section: str | None = None
    for line in content.splitlines():
        if line.startswith("## Now"):
            current_section = "Now"
        elif line.startswith("## Soon"):
            current_section = "Soon"
        elif line.startswith("## Backlog"):
            current_section = "Backlog"
        elif current_section and line.startswith("### "):
            sections[current_section].append(line[4:].strip())
    return dict(sections)


def verify_sigchain_integrity(engine: Engine) -> dict[str, Any]:
    """Verify sigchain integrity. Returns integrity status and chain length."""
    ok = engine.verify_sigchain()
    count = engine.ledger_count()
    return {"integrity_ok": ok, "chain_length": count}


def create_mcp_server(
    engine: Engine | None = None,
    pending_reviews: dict[str, Any] | None = None,
) -> FastMCP:
    """
    Create the aevum-maintainer MCP research interface.

    Six read-only tools expose sigchain state, compliance doc status, test
    count, backlog items, and integrity verification to Claude research sessions.
    """
    _engine = engine or Engine()
    _reviews: dict[str, Any] = pending_reviews if pending_reviews is not None else {}
    mcp = FastMCP("aevum-maintainer-research")

    @mcp.tool()
    def get_sigchain_summary_tool(n: int = 10) -> dict[str, Any]:
        """Summarize recent sigchain entries (last N)."""
        return get_sigchain_summary(_engine, n)

    @mcp.tool()
    def get_pending_reviews_tool() -> dict[str, Any]:
        """List open review IDs and their age in seconds."""
        return get_pending_reviews(_reviews)

    @mcp.tool()
    def get_compliance_pack_status_tool() -> dict[str, Any]:
        """Check which compliance docs exist and when last modified."""
        return get_compliance_pack_status()

    @mcp.tool()
    def get_test_count_tool() -> dict[str, Any]:
        """Return current test count and last run date from maintenance/last_state.json."""
        return get_test_count()

    @mcp.tool()
    def get_backlog_items_tool() -> dict[str, Any]:
        """Read Now/Soon/Backlog items from maintenance/enhancements.md."""
        return get_backlog_items()

    @mcp.tool()
    def verify_sigchain_integrity_tool() -> dict[str, Any]:
        """Verify sigchain integrity. Returns True/False + chain length."""
        return verify_sigchain_integrity(_engine)

    return mcp
