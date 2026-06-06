#!/usr/bin/env python3
"""
Aevum Docker MCP Gateway interceptor shim.

Standalone entry point — can be copied to any system on PATH and invoked
directly without installing the full package as a module.

Also installable as a console script:
  pip install aevum-mcp
  aevum-mcp-intercept  # resolves from PATH

Docker MCP Gateway usage:
  --interceptor=before:exec:aevum-mcp-intercept.py

Environment variables:
  AEVUM_DB_PATH   Path to SQLite ledger (default: aevum.db in cwd)
  AEVUM_ACTOR     Principal written to sigchain (default: mcp-gateway)
  AEVUM_DEV       Set to 1 for dev mode (NullPolicyEngine, no Cedar required)

Exit codes:
  0  — call allowed; original JSON written to stdout
  1  — call denied by barrier; JSON-RPC error written to stdout

SEP-1763 note: this shim targets Docker Gateway's existing process-exec format.
When SEP-1763 ships in the Python SDK, Aevum will provide a first-class
implementation. Track: github.com/modelcontextprotocol/experimental-ext-interceptors
"""
import sys

from aevum.mcp._intercept import main

sys.exit(main())
