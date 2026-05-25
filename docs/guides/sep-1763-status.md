# MCP SEP-1763 Interceptors — Status and Aevum Roadmap

## Current Status (as of Aevum v0.7.0)

MCP SEP-1763 (Interceptors API) defines a first-class interception hook for
MCP servers. As of this writing:

- **Specification status:** Draft
- **Python SDK support:** Planned (not yet implemented)
- **Track:** `github.com/modelcontextprotocol/experimental-ext-interceptors`

## Aevum's Current MCP Governance

Until SEP-1763 ships in the Python SDK, Aevum provides two complementary
integration points:

### 1. FastMCP Middleware (in-process)

`AevumGovernanceMiddleware` integrates with FastMCP 3.x servers using the
FastMCP Middleware protocol. This is the recommended path for FastMCP-based
deployments.

```python
from aevum.mcp.middleware import build_governance_middleware_class

GovernanceMiddleware = build_governance_middleware_class()
mcp.add_middleware(GovernanceMiddleware(kernel=kernel))
```

See: `aevum.mcp.middleware`, `aevum.mcp.gateway`

### 2. Docker MCP Gateway Shim (subprocess)

`aevum.mcp.interceptor` provides a standalone subprocess interceptor for
Docker MCP Gateway's `--interceptor=before:exec:<command>` hook.

```bash
--interceptor=before:exec:python3 -m aevum.mcp.interceptor
```

See: `docs/deployment/mcp-gateway.md`

## When SEP-1763 Ships

When SEP-1763 is ratified and implemented in the Python MCP SDK, Aevum will:

1. Implement `AevumSEP1763Interceptor` using the first-class interceptor API
2. Deprecate the Docker Gateway shim (maintain for one minor version cycle)
3. Provide a migration guide from shim to native interceptor

The FastMCP middleware approach will remain supported as a FastMCP-specific path.

## A2A Audit Middleware

Separate from MCP governance, Aevum's A2A audit middleware captures agent-to-agent
events at the ASGI transport layer:

```python
from aevum.agent.a2a_audit import AevumA2AAuditMiddleware

audited_app = AevumA2AAuditMiddleware(app, receipt_store=store)
```

This middleware captures events independently of `Task.history` (which A2A spec
§3.5.2 explicitly states is not guaranteed to be complete for audit purposes).
