"""
aevum.core.complications — Complication governance lifecycle.

  ComplicationRegistry  — 7-state machine: install/approve/suspend/decommission
  CircuitBreaker        — threshold-based, monotonic clock
  ManifestValidator     — schema + Ed25519 (optional)
  ConflictDetector      — capability overlap, fail-closed
  WebhookRegistry       — register/dispatch review events
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any

from aevum.core.complications.circuit_breaker import CircuitBreaker
from aevum.core.complications.conflict import ConflictDetector
from aevum.core.complications.manifest_validator import ManifestValidator
from aevum.core.complications.registry import ComplicationRegistry, ComplicationState
from aevum.core.complications.webhook import WebhookRegistry


def _run_coro(coro: Any) -> Any:
    """
    Run a coroutine from sync context.
    Handles the case where we are already inside a running event loop
    (e.g. FastAPI handlers) by delegating to a thread pool.
    """
    try:
        asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


__all__ = [
    "ComplicationRegistry",
    "ComplicationState",
    "CircuitBreaker",
    "ManifestValidator",
    "ConflictDetector",
    "WebhookRegistry",
    "_run_coro",
]
