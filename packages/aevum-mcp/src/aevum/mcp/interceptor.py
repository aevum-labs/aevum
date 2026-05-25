# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum MCP Docker Gateway Shim — standalone call interceptor.

Invoked by Docker MCP Gateway as a before-exec interceptor:
  --interceptor=before:exec:python3 -m aevum.mcp.interceptor

Protocol:
  stdin   → JSON-RPC call object from Docker Gateway
  stdout  → original JSON (on allow) or JSON error object (on deny)
  stderr  → human-readable diagnostic messages

Exit codes:
  0 = allow  — Docker Gateway passes the call through to the MCP server
  1 = deny   — Docker Gateway blocks the call; the caller receives an error
  2 = error  — Docker Gateway behavior is undefined (verify from Docker docs);
               conservative deployments should treat exit 2 as deny

Environment variables:
  AEVUM_RECEIPT_DB  — path to SQLite receipt store (required in production)
  AEVUM_DEV=1       — in-memory mode; skips Cedar, uses NullReceiptStore

Barriers checked:
  Barrier 1 (Crisis) — keyword-matching on all params text; always checked
  Barriers 2, 3, 4  — require runtime state not available to a stateless interceptor;
                       enforced by the full kernel, not this shim
  Barrier 5 (Provenance) — not checkable from a raw MCP call (no provenance field);
                            enforced by the full kernel on ingest
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
import uuid
from typing import Any

logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="[aevum-interceptor] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def _extract_text(obj: Any) -> str:
    """Recursively extract all string content from a JSON value."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_extract_text(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_extract_text(v) for v in obj)
    return ""


def _deny_response(call_id: Any, code: int, message: str) -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": call_id,
        "error": {"code": code, "message": message},
    })


def _store_receipt(method: str, outcome: str, audit_id: str) -> None:
    """
    Store an interceptor receipt in AEVUM_RECEIPT_DB if available.
    Non-blocking — failures are logged and silently ignored.
    """
    try:
        from aevum.core.sqlite_store import SqliteReceiptStore
        store = SqliteReceiptStore.from_env()
        blob = json.dumps({
            "interceptor": True,
            "outcome": outcome,
            "method": method,
            "audit_id": audit_id,
            "timestamp": time.time(),
        }, separators=(",", ":")).encode("utf-8")
        receipt_hash = hashlib.sha3_256(blob).hexdigest()
        store.put(receipt_hash=receipt_hash, blob=blob)
    except RuntimeError:
        # AEVUM_RECEIPT_DB not set and not in dev mode — no-op
        pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("receipt store failed: %s", exc)


def _check_barrier_1(text: str, call_id: Any) -> str | None:
    """
    Barrier 1 — Crisis content detection (unconditional, hardcoded).
    Returns a JSON deny-response string if the barrier fires, or None to allow.
    Skipped with a warning if aevum-core is not installed.
    """
    try:
        from aevum.core.barriers import BarrierError, crisis_barrier_check
        try:
            crisis_barrier_check(text)
        except BarrierError as exc:
            return _deny_response(call_id, -32001, f"Aevum Barrier 1 (Crisis): {exc}")
    except ImportError:
        logger.warning("aevum.core.barriers unavailable; Barrier 1 skipped")
    return None


def main() -> None:
    """Entry point for the Docker MCP Gateway interceptor."""
    try:
        raw = sys.stdin.read()
        call_data: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("JSON parse error: %s", exc)
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        logger.error("stdin read error: %s", exc)
        sys.exit(2)

    call_id: Any = call_data.get("id")
    method: str = call_data.get("method", "")
    params: Any = call_data.get("params", {})
    audit_id = str(uuid.uuid4())

    all_text = _extract_text(params)

    # Barrier 1 — Crisis content (unconditional, hardcoded per spec §09.3)
    deny = _check_barrier_1(all_text, call_id)
    if deny is not None:
        print(deny)
        _store_receipt(method, "deny:barrier1", audit_id)
        sys.exit(1)

    # All available checks passed — allow the call through
    _store_receipt(method, "allow", audit_id)
    sys.stdout.write(raw)
    sys.exit(0)


if __name__ == "__main__":
    main()
