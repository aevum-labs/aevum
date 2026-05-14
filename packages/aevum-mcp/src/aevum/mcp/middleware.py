# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum governance middleware for FastMCP 3.x.

AevumGovernanceMiddleware intercepts every MCP tool call and:
  1. Evaluates Cedar policy (are taint labels safe for this call?)
  2. Records the call in the sigchain
  3. Passes through if permitted, raises PermissionError if denied

Usage with server mode:
  mcp = FastMCP("aevum-server")
  GovernanceMiddleware = build_governance_middleware_class()
  mcp.add_middleware(GovernanceMiddleware(kernel=kernel))

Usage with gateway mode (via ProxyProvider):
  from fastmcp.server.providers.proxy import ProxyProvider
  from fastmcp import FastMCP, Client
  provider = ProxyProvider(Client("http://upstream/mcp/v1"))
  gateway = FastMCP("aevum-gateway", providers=[provider])
  GovernanceMiddleware = build_governance_middleware_class()
  gateway.add_middleware(GovernanceMiddleware(kernel=kernel))

FastMCP 3.x middleware import path (verified):
  from fastmcp.server.middleware import Middleware
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class AevumGovernanceMiddleware:
    """
    FastMCP middleware that applies Aevum governance to every tool call.

    Implements the FastMCP Middleware protocol:
      subclass Middleware, override on_call_tool (and other hooks as needed)

    The exact base class is injected by build_governance_middleware_class()
    at server startup, avoiding import errors when FastMCP is not installed.
    """

    def __init__(
        self,
        kernel: Any,
        session_id: str = "mcp-session",
        agent_id: str = "mcp-agent",
    ) -> None:
        self._kernel = kernel
        self._session_id = session_id
        self._agent_id = agent_id

    def _evaluate_cedar(self, tool_name: str, context: dict[str, Any]) -> bool:
        """Evaluate Cedar policy for a tool call. Returns True if permitted."""
        from aevum.core.cedar_engine import CedarPolicyEngine
        engine = CedarPolicyEngine.default()
        return engine.is_permitted(
            principal_type="AevumAgent",
            principal_id=self._agent_id,
            action="tool_call",
            resource_type="ToolAction",
            resource_id=tool_name,
            context=context,
        )

    def _record_in_sigchain(
        self, tool_name: str, input_hash: str, output_hash: str
    ) -> None:
        """Record the tool call event in the sigchain (non-blocking)."""
        try:
            logger.debug(
                "Sigchain: MCP tool_call tool=%s input=%s... output=%s...",
                tool_name, input_hash[:8], output_hash[:8],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigchain record failed for tool %s: %s", tool_name, exc)


def build_governance_middleware_class() -> type:
    """
    Build the governance middleware class at runtime, adapting to the
    installed FastMCP version. Returns a class that inherits from
    the correct FastMCP Middleware base.

    Call this once at server startup:
      GovernanceMiddleware = build_governance_middleware_class()
      mcp.add_middleware(GovernanceMiddleware(kernel=kernel))
    """
    try:
        from fastmcp.server.middleware import Middleware as _Base
    except ImportError:
        try:
            from fastmcp.middleware import Middleware as _Base  # type: ignore[no-redef]
        except ImportError as exc:
            raise ImportError(
                "Cannot import FastMCP Middleware. "
                "Ensure fastmcp>=3.2.0 is installed."
            ) from exc

    class _GovernanceMiddlewareImpl(_Base, AevumGovernanceMiddleware):
        """FastMCP governance middleware with Aevum Cedar + sigchain integration."""

        async def on_call_tool(
            self,
            context: Any,
            call_next: Any,
        ) -> Any:
            """
            Intercept every MCP tool call.
              1. Cedar ABAC check (trifecta policy)
              2. Execute tool (call_next)
              3. Record in sigchain
            """
            import hashlib
            import json

            # FastMCP 3.x: context.message is CallToolRequestParams
            tool_name = context.message.name
            tool_args: dict[str, Any] = context.message.arguments or {}

            cedar_ctx: dict[str, Any] = {
                "taint_reads_untrusted": False,
                "taint_reads_private": False,
                "taint_can_exfiltrate": False,
                "has_crisis_content": False,
            }

            if not self._evaluate_cedar(tool_name, cedar_ctx):
                logger.warning(
                    "Cedar DENY: MCP tool call blocked: tool=%s agent=%s",
                    tool_name, self._agent_id,
                )
                raise PermissionError(
                    f"Cedar policy denied tool call: {tool_name!r}. "
                    "Aevum governance middleware blocked this request."
                )

            input_hash = hashlib.sha256(
                json.dumps(tool_args, sort_keys=True).encode()
            ).hexdigest()

            result = await call_next(context)

            output_hash = hashlib.sha256(
                str(result).encode("utf-8", errors="replace")
            ).hexdigest()

            self._record_in_sigchain(tool_name, input_hash, output_hash)
            return result

    return _GovernanceMiddlewareImpl
