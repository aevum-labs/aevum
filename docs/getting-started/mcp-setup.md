# MCP Setup

`aevum-mcp` exposes all five governed functions as tools for any MCP-compatible host.

## Install

```bash
pip install aevum-mcp
```

## Configuration

All MCP hosts use the same configuration format. Add this to your MCP host's
configuration file:

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

### Claude Desktop

Config file location:

- macOS: `~/.claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Open (or create) the file and add the `aevum` entry inside `mcpServers`:

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

Restart Claude Desktop after saving.

### Cursor

Add to Cursor's MCP server configuration in **Settings → MCP**. Use the same
JSON block above.

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "aevum": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "aevum.mcp"]
    }
  }
}
```

### Other MCP-compatible hosts

The configuration format above uses standard MCP stdio transport.
Any MCP-compatible host that supports stdio transport will work.

## What you get

Once registered, the host has access to five governed tools:

| Tool | What it does |
|---|---|
| `ingest` | Write data through the governed membrane |
| `query` | Read context for a declared purpose |
| `review` | Request human approval for an action |
| `commit` | Append a named event to the episodic ledger |
| `replay` | Reconstruct any past decision |

All five are consent-gated and automatically logged to a local signed ledger.

## Verify

After configuration, ask your MCP host:

> "What tools do you have available from Aevum?"

It should list the five governed functions.

## Connecting to a persistent store

By default, `aevum-mcp` uses in-memory storage. For persistence, set environment
variables before launching:

```json
{
  "mcpServers": {
    "aevum": {
      "command": "python",
      "args": ["-m", "aevum.mcp"],
      "env": {
        "AEVUM_STORE": "oxigraph",
        "AEVUM_STORE_PATH": "/path/to/data"
      }
    }
  }
}
```
