# MCP Integration

Aevum provides two integration points for Model Context Protocol deployments:
FastMCP in-process middleware and a Docker MCP Gateway subprocess interceptor.
A first-class SEP-1763 interceptor is planned for when the Python SDK ships it.

## FastMCP middleware (in-process)

`AevumGovernanceMiddleware` integrates with FastMCP 3.x servers using the
FastMCP Middleware protocol. This is the recommended path for FastMCP-based
deployments.

```python
from aevum.mcp.middleware import build_governance_middleware_class
from aevum.core import Engine

kernel = Engine()
GovernanceMiddleware = build_governance_middleware_class()

# mcp is a FastMCP server instance
mcp.add_middleware(GovernanceMiddleware(kernel=kernel))
```

Every tool invocation through the FastMCP server is:
1. Cedar-evaluated before execution
2. Recorded as a sigchain entry in the episodic ledger
3. Assigned an `audit_id` for replay

See also: `aevum.mcp.middleware`, `aevum.mcp.gateway`.

## Docker MCP Gateway interceptor (subprocess)

For Docker MCP Gateway deployments, Aevum provides a standalone subprocess
interceptor that checks unconditional barriers without a running Aevum server.

```bash
--interceptor=before:exec:python3 -m aevum.mcp.interceptor
```

The interceptor receives the JSON-RPC call on stdin and exits with:

| Exit code | Meaning | Gateway behavior |
|-----------|---------|-----------------|
| `0` | Allow | Call passes through to MCP server |
| `1` | Deny | Call blocked; caller receives JSON-RPC error |
| `2` | Error | Treat conservatively as deny |

### What the interceptor captures

| Barrier | Checked by interceptor | Notes |
|---------|----------------------|-------|
| Barrier 1 — Crisis | Yes | Keyword-matching on all params text; always checked |
| Barrier 2 — Classification ceiling | No | Requires runtime kernel state |
| Barrier 3 — Consent | No | Requires runtime kernel state |
| Barrier 4 — Audit immutability | No | Requires runtime kernel state |
| Barrier 5 — Provenance | No | Enforced by kernel on `ingest`; not checkable from raw MCP call |

**Limitation:** The subprocess interceptor enforces only Barrier 1 (crisis
keyword detection). For full barrier enforcement (Barriers 2–5), use the
FastMCP middleware with a running Aevum kernel, or deploy behind an Aevum
HTTP server.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AEVUM_RECEIPT_DB` | Production | Path to SQLite receipt store (e.g. `/data/aevum.db`) |
| `AEVUM_DEV=1` | Dev/test only | In-memory mode; skips Cedar; never bypasses crisis barriers |

Do not set `AEVUM_DEV=1` in production.

For full Docker MCP Gateway setup, see `docs/deployment/mcp-gateway.md`.

## MCP audit trail

For recording MCP tool calls with full sigchain provenance (kernel required),
see `docs/guides/mcp-audit-trail.md`.

## SEP-1763 status

MCP SEP-1763 (Interceptors API) is still in **Draft** status as of v0.7.0.
The Python MCP SDK does not yet implement it.

When SEP-1763 ships in the Python SDK, Aevum will:
1. Implement `AevumSEP1763Interceptor` using the first-class interceptor API
2. Deprecate the Docker Gateway shim (one minor version cycle)
3. Provide a migration guide

The FastMCP middleware approach will continue to be supported as a
FastMCP-specific integration path.

For the full SEP-1763 roadmap, see `docs/guides/sep-1763-status.md`.
