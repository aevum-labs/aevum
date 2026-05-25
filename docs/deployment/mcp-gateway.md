# MCP Docker Gateway Integration

Aevum provides a standalone interceptor shim for use with Docker MCP Gateway.
The interceptor runs as a subprocess per call — it does not require a running
Aevum HTTP server.

## How It Works

Docker MCP Gateway supports `--interceptor=before:exec:<command>` hooks.
The interceptor receives the JSON-RPC call on stdin, checks Aevum's unconditional
barriers, and exits to signal allow or deny.

Exit codes (verified from Aevum interceptor source):

| Exit code | Meaning | Docker Gateway behavior |
|-----------|---------|------------------------|
| `0` | Allow | Passes the call through to the MCP server |
| `1` | Deny | Blocks the call; caller receives a JSON-RPC error |
| `2` | Error | Undefined per Docker MCP Gateway docs; treat conservatively as deny |

Barrier checked by the interceptor:

- **Barrier 1 (Crisis)** — keyword-matching on all params text; always checked
- **Barriers 2–4** — require runtime kernel state; enforced by the full Aevum kernel, not this shim
- **Barrier 5 (Provenance)** — enforced by the kernel on `ingest`; not checkable from a raw MCP call

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `AEVUM_RECEIPT_DB` | Production | Path to SQLite receipt store (e.g. `/data/aevum.db`) |
| `AEVUM_DEV=1` | Dev/test only | In-memory mode; skips Cedar, uses NullReceiptStore |

**Do not set `AEVUM_DEV=1` in production.** Dev mode bypasses Cedar policy
evaluation. It never bypasses crisis barriers (Barrier 1 is unconditional).

The environment variable for the receipt database is `AEVUM_RECEIPT_DB`
(verified from `aevum.core.sqlite_store.SqliteReceiptStore.from_env()`).
`AEVUM_DB_PATH` is **not** used.

## Docker Compose Example

```yaml
services:
  mcp-gateway:
    image: docker/mcp-gateway:latest
    environment:
      - AEVUM_RECEIPT_DB=/data/aevum.db
      - AEVUM_DEV=0
    volumes:
      - aevum-data:/data
    command: >
      --interceptor=before:exec:python3 -m aevum.mcp.interceptor
      --mcp-server=http://your-mcp-server:8080/mcp/v1

  aevum-db-init:
    image: python:3.11-slim
    volumes:
      - aevum-data:/data
    command: python3 -c "from aevum.core.sqlite_store import SqliteReceiptStore; SqliteReceiptStore('/data/aevum.db')"

volumes:
  aevum-data:
```

## Entry Point

The interceptor is registered as an entry point in `aevum-mcp`:

```
aevum-mcp-intercept = "aevum.mcp.interceptor:main"
```

It can also be invoked directly as a Python module:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | python3 -m aevum.mcp.interceptor
echo "exit: $?"
```

## Limitations

- **Stateless per call** — the interceptor reads from `AEVUM_RECEIPT_DB` on
  each invocation. In-memory sigchain state (e.g. session-scoped consent grants)
  is not available to the interceptor.
- **One process per MCP call** — startup cost is incurred on every call.
  For high-throughput deployments, use the in-process `AevumGovernanceMiddleware`
  via FastMCP instead (see `aevum.mcp.middleware`).
- **Barriers 2–4 require the full kernel** — the shim enforces only Barrier 1
  (crisis detection). Full barrier enforcement requires the Aevum kernel.

## SEP-1763 Status Note

MCP SEP-1763 (Interceptors API) is currently **Draft** status. The Python SDK
support is listed as **Planned** in the experimental-ext-interceptors repository.

> When MCP SEP-1763 ships in the Python SDK, Aevum will provide a first-class
> in-process implementation that replaces this Docker Gateway shim. Track:
> `github.com/modelcontextprotocol/experimental-ext-interceptors`

Until SEP-1763 is stable, Aevum's MCP governance uses:
1. **FastMCP middleware** (`AevumGovernanceMiddleware`) — in-process, for FastMCP servers
2. **Docker Gateway shim** (`aevum.mcp.interceptor`) — subprocess, for Docker MCP Gateway
