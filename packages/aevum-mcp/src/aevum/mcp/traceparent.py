# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
W3C traceparent / tracestate / baggage injection and extraction for MCP.

Per OTel SEP-414 (draft), traceparent is carried in the JSON-RPC ``_meta``
field of MCP requests and responses:

  {
    "method": "tools/call",
    "params": {
      "_meta": {
        "traceparent": "00-<trace-id>-<parent-id>-01",
        "tracestate": "",
        "baggage": ""
      },
      ...
    }
  }

Opt-out: set AEVUM_MCP_SKIP_TRACE_INJECT=1 to disable injection.
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from typing import Any

logger = logging.getLogger(__name__)

_TRACEPARENT_RE = re.compile(
    r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
)


def should_inject() -> bool:
    """Return True unless AEVUM_MCP_SKIP_TRACE_INJECT=1 is set."""
    return os.environ.get("AEVUM_MCP_SKIP_TRACE_INJECT", "").strip() != "1"


def make_traceparent() -> str:
    """Generate a new W3C traceparent: 00-{32hex}-{16hex}-01."""
    trace_id = uuid.uuid4().hex           # 16 bytes = 32 hex chars
    parent_id = uuid.uuid4().hex[:16]     # 8 bytes = 16 hex chars
    return f"00-{trace_id}-{parent_id}-01"


def inject_into_meta(params: dict[str, Any]) -> str:
    """
    Inject traceparent / tracestate / baggage into params["_meta"].
    Creates ``_meta`` if absent.  Returns the injected traceparent value.
    Respects AEVUM_MCP_SKIP_TRACE_INJECT=1.
    """
    if not should_inject():
        return ""

    meta = params.get("_meta")
    if meta is None:
        meta = {}
        params["_meta"] = meta

    traceparent = make_traceparent()
    meta["traceparent"] = traceparent
    meta.setdefault("tracestate", "")
    meta.setdefault("baggage", "")

    logger.debug("MCP: injected traceparent=%s...", traceparent[:20])
    return traceparent


def extract_from_meta(params: dict[str, Any]) -> str | None:
    """
    Extract the incoming traceparent from params["_meta"].
    Returns the traceparent string if present and valid, else None.
    """
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None

    tp = meta.get("traceparent")
    if not isinstance(tp, str):
        return None

    if not _TRACEPARENT_RE.match(tp):
        logger.warning("MCP: incoming traceparent has invalid format: %r", tp[:40])
        return None

    return tp


def traceparent_to_trace_id(traceparent: str) -> str | None:
    """
    Extract the 32-hex trace-id segment from a validated traceparent.
    Returns None if the format is invalid.
    """
    parts = traceparent.split("-")
    if len(parts) != 4 or len(parts[1]) != 32:
        return None
    return parts[1]
