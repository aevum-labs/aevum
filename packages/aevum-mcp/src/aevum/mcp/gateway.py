# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum MCP gateway — proxy any MCP server with governance layer.

Every tool call through this gateway is:
  1. Cedar-evaluated (AevumGovernanceMiddleware)
  2. Recorded in the sigchain
  3. Forwarded to the upstream MCP server

Usage:
  from aevum.mcp.gateway import AevumGateway
  gateway = await AevumGateway.create(
      upstream_url="http://any-mcp-server:8080/mcp/v1",
      kernel=kernel,
  )
  gateway.run(transport="http", port=8081)
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class AevumGateway:
    """
    Creates a governed MCP gateway that proxies any upstream MCP server.

    Uses FastMCP 3.x ProxyProvider + AevumGovernanceMiddleware.
    """

    @classmethod
    async def create(
        cls,
        upstream_url: str,
        kernel: Any,
        name: str = "aevum-gateway",
        agent_id: str = "gateway-agent",
    ) -> Any:
        """
        Create a FastMCP gateway server that proxies upstream_url.

        Returns a FastMCP server instance ready to call .run() on.
        """
        from fastmcp import Client, FastMCP

        from aevum.mcp.middleware import build_governance_middleware_class

        # ProxyProvider requires a factory callable (not a Client instance).
        # FastMCP 3.x canonical path; fastmcp.server.proxy is deprecated.
        def _client_factory() -> Client[Any]:
            return Client(upstream_url)

        try:
            from fastmcp.server.providers.proxy import ProxyProvider
            gateway_server = FastMCP(name, providers=[ProxyProvider(_client_factory)])
        except ImportError:
            # as_proxy() accepts a URL string directly and is not async.
            logger.warning(
                "ProxyProvider not found — falling back to FastMCP.as_proxy(). "
                "Upgrade to fastmcp>=3.2.0 for security fixes (CVE-2026-27124)."
            )
            gateway_server = FastMCP.as_proxy(upstream_url, name=name)

        GovernanceMiddleware = build_governance_middleware_class()
        gateway_server.add_middleware(
            GovernanceMiddleware(kernel=kernel, agent_id=agent_id)
        )

        logger.info(
            "Aevum MCP gateway ready: upstream=%s name=%s", upstream_url, name
        )
        return gateway_server
