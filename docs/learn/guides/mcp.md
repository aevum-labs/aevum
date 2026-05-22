---
description: "W3C traceparent injection for MCP tool calls via aevum-mcp."
---

# MCP Traceparent Guide

`aevum-mcp` automatically injects W3C traceparent context into every MCP
JSON-RPC request, making MCP tool calls traceable across your OTel backend.

---

## How it works

Per OTel SEP-414 (draft), traceparent is carried in the `_meta` field of MCP
JSON-RPC requests:

```json
{
  "method": "tools/call",
  "params": {
    "_meta": {
      "traceparent": "00-<trace-id>-<parent-id>-01",
      "tracestate": "",
      "baggage": ""
    }
  }
}
```

The `aevum-mcp` package provides two functions for client-side injection and
server-side extraction.

---

## Install

```bash
pip install "aevum-core[mcp]"
```

---

## Client-side injection

```python
from aevum.mcp.traceparent import inject_into_meta

params = {"name": "search", "arguments": {"query": "aevum"}}
traceparent = inject_into_meta(params)
# params["_meta"]["traceparent"] is now set
print(traceparent)  # 00-abc123...-def456...-01
```

The injected traceparent is also recorded in the Aevum sigchain for
correlation with downstream spans.

---

## Server-side extraction

```python
from aevum.mcp.traceparent import extract_from_meta

incoming_params = {
    "_meta": {"traceparent": "00-abc123...-def456...-01"},
    "name": "search",
}
traceparent = extract_from_meta(incoming_params)
if traceparent:
    print(f"Incoming trace: {traceparent}")
```

Invalid traceparent formats are logged and rejected — `extract_from_meta`
returns `None` for malformed values.

---

## Opt-out

Set `AEVUM_MCP_SKIP_TRACE_INJECT=1` to disable injection entirely:

```bash
export AEVUM_MCP_SKIP_TRACE_INJECT=1
```

This is useful when the MCP host manages its own tracing context.

---

## Compatibility matrix (v0.6.0)

Tested in CI as part of Phase A (gate items G-17 and G-18):

| MCP host | Min version | CI status |
|---|---|---|
| fastmcp | `>=3.2.0` | ✓ 24 round-trip integration tests |
| Claude Desktop | MCP 1.0 | Tested via fastmcp mock |
| VS Code MCP | MCP 1.0 | Tested via fastmcp mock |

The traceparent round-trip (inject → transmit → extract → validate) is
verified in `packages/aevum-mcp/tests/test_traceparent.py`.

Note: `fastmcp>=3.2.0` is required to mitigate CVE-2026-27124 and
CVE-2025-64340.

---

## Next steps

- [Anthropic adapter guide](/learn/guides/anthropic/) — traceparent for direct SDK calls
- [AevumOTelBridge](/learn/otel-bridge/) — route sigchain events to your OTel backend
- [MCP Setup guide](/getting-started/mcp-setup/) — configure MCP tools in your host
