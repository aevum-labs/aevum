# Docker MCP Gateway — Aevum Interceptor

Aevum ships a process-exec interceptor for Docker MCP Gateway.
Every `tools/call` request is checked against Aevum's five unconditional
barriers before it reaches the MCP server.

## How It Works

```
Client → Docker MCP Gateway → [aevum-mcp-intercept] → MCP Server
                                       |
                             Exit 0: allow (original JSON)
                             Exit 1: deny  (JSON-RPC error)
```

The shim reads the JSON-RPC call from stdin, runs `Engine.ingest()` to
trigger all five barriers, then exits with 0 (allow) or 1 (deny). It does
not require a running Aevum HTTP server — it talks to the local SQLite
ledger directly.

## Installation

```bash
pip install aevum-mcp
which aevum-mcp-intercept   # confirms it is on PATH
```

## Docker Compose

```yaml
services:
  mcp-gateway:
    image: docker/mcp-gateway:latest
    command:
      - --interceptor=before:exec:aevum-mcp-intercept
      - --target=http://mcp-server:8080
    environment:
      AEVUM_DB_PATH: /data/aevum.db
      AEVUM_ACTOR:   mcp-gateway
    volumes:
      - aevum-data:/data

  mcp-server:
    image: your/mcp-server:latest

volumes:
  aevum-data:
```

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `AEVUM_DB_PATH` | `aevum.db` in cwd | Path to SQLite ledger |
| `AEVUM_ACTOR` | `mcp-gateway` | Principal written to sigchain entries |
| `AEVUM_DEV` | unset | Set to `1` for dev mode (NullPolicyEngine, no Cedar required) |

**Do not set `AEVUM_DEV=1` in production.** Dev mode bypasses Cedar policy
evaluation. It never bypasses the unconditional barriers (Barrier 1 is always enforced).

## Exit Codes

| Exit code | Meaning | Docker Gateway behavior |
|---|---|---|
| `0` | Allow | Passes the call through to the MCP server |
| `1` | Deny | Blocks the call; caller receives a JSON-RPC error |

The shim never exits with any code other than `0` or `1`. On any unexpected
error it fails open (exit 0) and logs a diagnostic to stderr — a misconfigured
shim must never silently block calls.

## Passthrough Methods

These methods bypass barrier checks and are always allowed through:

- `tools/list`
- `resources/list`
- `prompts/list`
- `initialize`
- `ping`

## Barriers Enforced

| Barrier | What it checks | Enforced here |
|---|---|---|
| 1 — Crisis Detection | Self-harm / dangerous-content keywords | Yes (via `Engine.ingest`) |
| 2 — Classification Ceiling | Above-clearance query blocking | Yes (via `Engine.ingest`) |
| 3 — Consent | Active consent grant for actor + subject | Yes (via `Engine.ingest`) |
| 4 — Audit Immutability | Append-only ledger invariant | Structural in ledger |
| 5 — Provenance | Chain of custody present | Yes (via `Engine.ingest`) |

## Console Script vs. Standalone Shim

Two delivery modes — identical behaviour:

| Mode | Command | When to use |
|---|---|---|
| Console script | `aevum-mcp-intercept` | `aevum-mcp` installed via pip |
| Standalone shim | `python3 aevum-mcp-intercept.py` | Drop-in, minimal dependencies |

The standalone shim lives at `packages/aevum-mcp/bin/aevum-mcp-intercept.py`.

## Smoke Test

```bash
# Allow — tools/list passthrough
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | AEVUM_DEV=1 aevum-mcp-intercept
echo "Exit: $?"   # must be 0

# Deny — crisis content
printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ingest","arguments":{"data":{"content":"I want to kill myself"}}}}' \
  | AEVUM_DEV=1 aevum-mcp-intercept
echo "Exit: $?"   # must be 1
```

## SEP-1763 Status

MCP SEP-1763 (Interceptors API) is currently **Draft** status. Python support
is listed as **Planned** in `modelcontextprotocol/experimental-ext-interceptors`
with no merged implementation yet.

This shim targets Docker Gateway's existing process-exec format and is the
production path today. When SEP-1763 ships in the Python SDK, Aevum will
provide a first-class in-process implementation.

Track: `github.com/modelcontextprotocol/experimental-ext-interceptors`
