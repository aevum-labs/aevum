# MCP Integration

Aevum provides two integration points for Model Context Protocol deployments:
FastMCP in-process middleware and a Docker MCP Gateway subprocess interceptor.
A first-class SEP-1763 interceptor is planned for when the Python SDK ships it.

## Prerequisites

```bash
pip install aevum-mcp
```

`aevum-mcp` depends on `aevum-core`, so installing it brings in the full kernel.

## Starting the MCP server

`aevum-mcp` runs as a **stdio transport** server — the host process launches it
and communicates over stdin/stdout:

```bash
# Using the installed CLI entry point:
aevum-mcp

# Or directly via Python:
python -m aevum.mcp
```

The server starts an `Engine` with in-memory defaults. For persistent storage,
pass a custom `Engine` instance by starting the server from Python:

```python
from aevum.core.engine import Engine
from aevum.mcp import create_server

engine = Engine()          # configure graph_store, sigchain, etc. here
mcp = create_server(engine=engine)
mcp.run(transport="stdio")
```

## Claude Code configuration

Add the server to `.claude/mcp.json` (project-scoped) or `~/.claude/mcp.json`
(user-global):

```json
{
  "mcpServers": {
    "aevum": {
      "command": "python",
      "args": ["-m", "aevum.mcp"]
    }
  }
}
```

Or, if `aevum-mcp` is on your PATH:

```json
{
  "mcpServers": {
    "aevum": {
      "command": "aevum-mcp"
    }
  }
}
```

After adding the config, restart Claude Code. Run `/mcp` in the terminal to
confirm `aevum` appears in the server list.

## Cursor configuration

Add to `.cursor/mcp.json` at the project root or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "aevum": {
      "command": "python",
      "args": ["-m", "aevum.mcp"]
    }
  }
}
```

## Windsurf configuration

Add to `~/.windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "aevum": {
      "command": "python",
      "args": ["-m", "aevum.mcp"]
    }
  }
}
```

## Available tools

Once connected, the following tools are available to the AI coding assistant:

| Tool | Aevum function | Description |
|------|---------------|-------------|
| `ingest` | RELATE | Move data through the governed membrane into the knowledge graph. Requires an active consent grant. |
| `query` | NAVIGATE | Traverse the knowledge graph for a declared purpose. Returns context filtered by consent and classification. |
| `review` | GOVERN | Poll or act on a pending human review gate (`approve` / `veto`). |
| `commit` | REMEMBER | Append a named event directly to the episodic ledger. |
| `replay` | replay | Reconstruct any past decision faithfully from the ledger. |
| `create_task` | — | Create an A2A-compatible task backed by the ledger. Returns an `audit_id` as the task ID. |
| `get_task` | — | Retrieve current state of a task by its `audit_id`. |
| `relate` | RELATE | Ingest a plain-text fact with a subject and source. Convenience alias for `ingest`. |
| `navigate` | NAVIGATE | Assemble governed context for a purpose. Convenience alias for `query`. |
| `govern` | GOVERN | Request a human checkpoint for a proposed action. Convenience alias for `review`. |

## Consent and provenance

Every `ingest` and `query` tool call requires an active consent grant for the
`actor` + `subject_id` + `purpose` combination. Without a grant, the tool
returns `status: "error"` with `error_code: "consent_required"`.

To add a consent grant before starting the server:

```python
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
mcp.run(transport="stdio")
```

For full consent and sigchain setup, see [MCP Audit Trails](mcp-audit-trail.md).

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

## Verifying tool calls

Each tool call returns an `audit_id` in the `OutputEnvelope`. Use `aevum verify`
to confirm the sigchain covering that session is intact:

```bash
aevum verify <session_id>
# exit 0 → VERIFIED: chain intact
# exit 1 → TAMPERED: chain broken
```

To inspect individual entries, use `aevum verify-receipt`:

```bash
aevum verify-receipt <receipt_file>
```

See the [CLI Reference](../reference/cli.md) for the full command reference.

## Next steps

- [OpenAI Agents SDK Integration](openai-agents.md) — govern every tool call
  and agent handoff with `AevumAgentHooks`
- [MCP Audit Trails](mcp-audit-trail.md) — detailed sigchain setup and consent
  grant management for MCP deployments
- [Deployment Guides](../learn/deployment.md) — production-grade storage,
  key management, and Docker MCP Gateway setup
