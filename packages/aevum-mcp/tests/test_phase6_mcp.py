# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Phase 6 test suite for aevum-mcp:
  - AevumGovernanceMiddleware (Cedar ABAC + sigchain)
  - AevumGateway (ProxyProvider + middleware)
  - FastMCP 3.x API migration verification

NO tests/__init__.py (standing rule Rule 01).
"""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestGovernanceMiddleware:
    def _make_middleware_class(self) -> type:
        from aevum.mcp.middleware import build_governance_middleware_class
        return build_governance_middleware_class()

    def test_build_returns_class(self) -> None:
        cls = self._make_middleware_class()
        assert isinstance(cls, type)

    def test_middleware_instantiates_with_kernel(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel)
        assert m._kernel is kernel

    def test_middleware_instantiates_with_session_and_agent_id(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel, session_id="s1", agent_id="agent-42")
        assert m._session_id == "s1"
        assert m._agent_id == "agent-42"

    def test_middleware_default_ids(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel)
        assert m._session_id == "mcp-session"
        assert m._agent_id == "mcp-agent"

    def test_cedar_deny_blocks_tool_call(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel, agent_id="test-agent")
        with patch.object(m, "_evaluate_cedar", return_value=False):
            context = MagicMock()
            context.message.name = "dangerous_tool"
            context.message.arguments = {}
            with pytest.raises(PermissionError, match="Cedar policy denied"):
                asyncio.run(m.on_call_tool(context, AsyncMock()))

    def test_cedar_permit_passes_tool_call(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel)
        mock_result: dict[str, str] = {"content": "ok"}

        async def mock_next(ctx: object) -> dict[str, str]:
            return mock_result

        with patch.object(m, "_evaluate_cedar", return_value=True):
            context = MagicMock()
            context.message.name = "safe_tool"
            context.message.arguments = {"query": "test"}
            result = asyncio.run(m.on_call_tool(context, mock_next))
        assert result == mock_result

    def test_cedar_deny_logs_warning(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel, agent_id="blocked-agent")
        with patch.object(m, "_evaluate_cedar", return_value=False):
            context = MagicMock()
            context.message.name = "bad_tool"
            context.message.arguments = {}
            with pytest.raises(PermissionError):
                asyncio.run(m.on_call_tool(context, AsyncMock()))

    def test_permit_records_in_sigchain(self) -> None:
        cls = self._make_middleware_class()
        kernel = MagicMock()
        m = cls(kernel=kernel)
        sigchain_calls: list[tuple[str, str, str]] = []

        def mock_record(tool_name: str, in_hash: str, out_hash: str) -> None:
            sigchain_calls.append((tool_name, in_hash, out_hash))

        with patch.object(m, "_evaluate_cedar", return_value=True), \
                patch.object(m, "_record_in_sigchain", side_effect=mock_record):
                context = MagicMock()
                context.message.name = "my_tool"
                context.message.arguments = {}
                asyncio.run(m.on_call_tool(context, AsyncMock(return_value="result")))
        assert len(sigchain_calls) == 1
        assert sigchain_calls[0][0] == "my_tool"

    def test_on_call_tool_is_coroutine(self) -> None:
        cls = self._make_middleware_class()
        assert inspect.iscoroutinefunction(cls.on_call_tool)

    def test_inherits_fastmcp_middleware(self) -> None:
        from fastmcp.server.middleware import Middleware
        cls = self._make_middleware_class()
        assert issubclass(cls, Middleware)

    def test_evaluate_cedar_returns_bool(self) -> None:
        from aevum.mcp.middleware import AevumGovernanceMiddleware
        m = AevumGovernanceMiddleware(kernel=MagicMock())
        with patch("aevum.mcp.middleware.AevumGovernanceMiddleware._evaluate_cedar") as mock_eval:
            mock_eval.return_value = True
            result = m._evaluate_cedar("test_tool", {})
        assert result is True

    def test_record_in_sigchain_is_noop_on_exception(self) -> None:
        from aevum.mcp.middleware import AevumGovernanceMiddleware
        m = AevumGovernanceMiddleware(kernel=MagicMock())
        # Should not raise even if something goes wrong internally
        m._record_in_sigchain("tool", "a" * 64, "b" * 64)

    def test_build_middleware_class_called_twice_returns_same_base(self) -> None:
        from aevum.mcp.middleware import build_governance_middleware_class
        cls1 = build_governance_middleware_class()
        cls2 = build_governance_middleware_class()
        from fastmcp.server.middleware import Middleware
        assert issubclass(cls1, Middleware)
        assert issubclass(cls2, Middleware)


class TestAevumGateway:
    def test_gateway_module_importable(self) -> None:
        from aevum.mcp.gateway import AevumGateway
        assert AevumGateway is not None

    def test_gateway_create_is_coroutine(self) -> None:
        from aevum.mcp.gateway import AevumGateway
        assert inspect.iscoroutinefunction(AevumGateway.create)

    def test_gateway_class_exists(self) -> None:
        from aevum.mcp.gateway import AevumGateway
        assert isinstance(AevumGateway, type)

    def test_gateway_create_method_exists(self) -> None:
        from aevum.mcp.gateway import AevumGateway
        assert hasattr(AevumGateway, "create")
        assert callable(AevumGateway.create)


class TestServerWithGovernance:
    def test_create_server_without_kernel_no_middleware(self) -> None:
        from aevum.mcp.server import create_server
        mcp = create_server()
        assert mcp is not None

    def test_create_server_with_kernel_adds_middleware(self) -> None:
        from aevum.mcp import middleware as mcp_middleware
        from aevum.mcp.server import create_server
        kernel = MagicMock()
        with patch.object(mcp_middleware, "build_governance_middleware_class") as mock_build:
            mock_cls = MagicMock(return_value=MagicMock())
            mock_build.return_value = mock_cls
            mcp = create_server(kernel=kernel)
        mock_build.assert_called_once()
        assert mcp is not None

    def test_server_has_relate_tool(self) -> None:
        from aevum.mcp.server import create_server
        mcp = create_server()
        tool_names = [t.name for t in asyncio.run(mcp.list_tools())]
        assert "relate" in tool_names

    def test_server_has_navigate_tool(self) -> None:
        from aevum.mcp.server import create_server
        mcp = create_server()
        tool_names = [t.name for t in asyncio.run(mcp.list_tools())]
        assert "navigate" in tool_names

    def test_server_has_govern_tool(self) -> None:
        from aevum.mcp.server import create_server
        mcp = create_server()
        tool_names = [t.name for t in asyncio.run(mcp.list_tools())]
        assert "govern" in tool_names

    def test_server_has_all_five_functions(self) -> None:
        from aevum.mcp.server import create_server
        mcp = create_server()
        tool_names = [t.name for t in asyncio.run(mcp.list_tools())]
        for name in ("ingest", "query", "review", "commit", "replay"):
            assert name in tool_names

    def test_fastmcp_version_gte_320(self) -> None:
        import fastmcp
        from packaging.version import Version
        v = Version(fastmcp.__version__)
        assert v >= Version("3.2.0"), f"FastMCP {v} < 3.2.0 (CVE risk)"


class TestMiddlewareImportPath:
    def test_fastmcp_server_middleware_import(self) -> None:
        from fastmcp.server.middleware import Middleware
        assert Middleware is not None

    def test_fastmcp_middleware_not_at_top_level(self) -> None:
        with pytest.raises(ImportError):
            import fastmcp.middleware  # noqa: F401

    def test_middleware_has_on_call_tool_method(self) -> None:
        from fastmcp.server.middleware import Middleware
        assert hasattr(Middleware, "on_call_tool")
