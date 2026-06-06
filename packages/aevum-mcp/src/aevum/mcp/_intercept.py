# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Core logic for the Aevum Docker MCP Gateway interceptor shim.

Reads a JSON-RPC call from stdin, runs it through aevum-core's five
unconditional barriers via Engine.ingest(), and exits to signal allow/deny.

Exit codes:
  0  — allow; original JSON written to stdout
  1  — deny;  JSON-RPC error object written to stdout

On any unexpected exception the shim fails open (exit 0) and logs to stderr
so that a misconfigured or partially-installed shim never silently blocks calls.

Consumed by:
  - packages/aevum-mcp/bin/aevum-mcp-intercept.py  (standalone executable)
  - pyproject.toml console_script aevum-mcp-intercept
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Any

_PASSTHROUGH_METHODS: frozenset[str] = frozenset({
    "tools/list",
    "resources/list",
    "prompts/list",
    "initialize",
    "ping",
})


def _allow(raw: str) -> int:
    sys.stdout.write(raw)
    sys.stdout.flush()
    return 0


def _deny(call_id: Any, reason: str, barrier: str) -> int:
    error: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": call_id,
        "error": {
            "code": -32001,
            "message": f"Aevum governance barrier denied: {reason}",
            "data": {
                "barrier": barrier,
                "actor": os.environ.get("AEVUM_ACTOR", "mcp-gateway"),
                "aevum": True,
            },
        },
    }
    sys.stdout.write(json.dumps(error))
    sys.stdout.flush()
    return 1


def _run_barriers(call: dict[str, Any], raw: str) -> int:
    method: str = call.get("method", "")
    call_id: Any = call.get("id")
    actor: str = os.environ.get("AEVUM_ACTOR", "mcp-gateway")

    if method in _PASSTHROUGH_METHODS:
        return _allow(raw)

    params: dict[str, Any] = call.get("params", {}) or {}
    tool_name: str = params.get("name", method) or method
    arguments: dict[str, Any] = params.get("arguments", {}) or {}

    try:
        from aevum.core.engine import Engine

        engine = Engine()
        envelope = engine.ingest(
            data={"tool": tool_name, "arguments": arguments},
            actor=actor,
            provenance={
                "source_id": "mcp-gateway",
                "classification": 0,
                "chain_of_custody": ["mcp-gateway"],
            },
            purpose="mcp-gateway-intercept",
            subject_id=tool_name,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[aevum-intercept] ERROR: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return _allow(raw)

    if isinstance(envelope, dict):
        status: str = envelope.get("status", "ok")
        data_field: Any = envelope.get("data", {})
        error_code: str = (data_field.get("error_code", status) if isinstance(data_field, dict) else status)
    else:
        status = getattr(envelope, "status", "ok")
        data_field = getattr(envelope, "data", None)
        error_code = (
            data_field.get("error_code", status)
            if isinstance(data_field, dict)
            else status
        )

    if status == "ok":
        return _allow(raw)
    elif status == "crisis":
        return _deny(call_id, "crisis content detected", "crisis")
    else:
        return _deny(call_id, str(error_code), "barrier")


def main() -> int:
    """Entry point for the Docker MCP Gateway interceptor."""
    raw = sys.stdin.read()
    if not raw.strip():
        return 0

    try:
        call = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return _allow(raw)

    if not isinstance(call, dict):
        return _allow(raw)

    try:
        return _run_barriers(call, raw)
    except Exception as exc:  # noqa: BLE001
        print(f"[aevum-intercept] UNEXPECTED ERROR (failing open): {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return _allow(raw)


if __name__ == "__main__":
    sys.exit(main())
