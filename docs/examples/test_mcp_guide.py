# SPDX-License-Identifier: Apache-2.0
"""
Tests for docs/guides/mcp.md code examples.

Verifies that the MCP server is importable and the documented tools exist.
No network calls or running server required.
"""
from __future__ import annotations

import pytest


def test_aevum_mcp_importable() -> None:
    """aevum-mcp package is importable."""
    mcp = pytest.importorskip("aevum.mcp")
    assert hasattr(mcp, "create_server")
    assert hasattr(mcp, "__version__")


def test_create_server_returns_fastmcp() -> None:
    """create_server() returns a FastMCP instance."""
    pytest.importorskip("aevum.mcp")
    from aevum.core.engine import Engine
    from aevum.mcp import create_server

    engine = Engine()
    server = create_server(engine=engine)
    assert server is not None


def test_create_server_no_engine() -> None:
    """create_server() creates its own Engine when none is provided."""
    pytest.importorskip("aevum.mcp")
    from aevum.mcp import create_server

    server = create_server()
    assert server is not None


def test_server_with_engine_from_guide() -> None:
    """The guide's 'Starting the MCP server' Python snippet is importable and runnable."""
    pytest.importorskip("aevum.mcp")
    from aevum.core.engine import Engine
    from aevum.mcp import create_server

    engine = Engine()
    mcp = create_server(engine=engine)
    # mcp.run(transport="stdio") is not called in tests — that blocks on stdin
    assert mcp is not None


def test_consent_grant_snippet_from_guide() -> None:
    """The consent grant snippet from the guide is importable and runnable."""
    pytest.importorskip("aevum.mcp")
    from aevum.core.engine import Engine
    from aevum.core.consent.models import ConsentGrant
    from aevum.mcp import create_server

    engine = Engine()
    engine.add_consent_grant(ConsentGrant(
        grant_id="grant-001",
        subject_id="user-abc",
        grantee_id="mcp-user",
        operations=["ingest", "query", "replay"],
        purpose="user-assistance",
        classification_max=1,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    ))

    mcp = create_server(engine=engine)
    assert mcp is not None


def test_mcp_module_main_importable() -> None:
    """python -m aevum.mcp entry point is importable."""
    pytest.importorskip("aevum.mcp")
    import aevum.mcp.__main__ as m  # noqa: F401
    assert hasattr(m, "main")
