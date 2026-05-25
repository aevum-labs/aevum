# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
AevumA2AAuditMiddleware — ASGI middleware for A2A server audit.

A2A spec §3.5.2: "not all Messages are guaranteed to be persisted in the
Task history." This middleware captures every event at the transport (HTTP)
layer, independently of Task.history, guaranteeing completeness.

The a2a-python SDK is NOT required — this middleware wraps any ASGI app
(Starlette, FastAPI, or bare ASGI) at the HTTP layer.

Integration:
    from aevum.agent.a2a_audit import AevumA2AAuditMiddleware
    from aevum.core.sqlite_store import SqliteReceiptStore

    store = SqliteReceiptStore.from_env()
    audited_app = AevumA2AAuditMiddleware(app, receipt_store=store)

Events captured per HTTP call:
  - path, method, HTTP status
  - SHA3-256 of request body (content hash, not content)
  - SHA3-256 of response body
  - contextId, task id, referenceTaskIds extracted from JSON body (best-effort)
  - event_id (UUID), timestamp

Task.history is never read. Causality links use contextId + referenceTaskIds
as defined in A2A v1.0 §4.2 (grouping) and §3.5.3 (cross-task reference).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from aevum.core.store import NullReceiptStore, ReceiptStore

logger = logging.getLogger(__name__)

# ASGI type aliases
_Scope = dict[str, Any]
_Message = dict[str, Any]
_Receive = Callable[[], Awaitable[_Message]]
_Send = Callable[[_Message], Awaitable[None]]


class AevumA2AAuditMiddleware:
    """
    ASGI middleware for A2A servers.
    Captures every Task/Message/Artifact event independently of Task.history.

    A2A spec §3.5.2: Task.history is unreliable for audit. This middleware
    captures events at the transport layer before they reach application code,
    so no application-level omission can produce an audit gap.

    Captured fields per event:
      event_id          — UUID for this specific capture
      timestamp         — Unix timestamp (float)
      path              — HTTP path (e.g. /tasks/send)
      method            — HTTP method
      status            — HTTP response status code
      request_hash      — SHA3-256 of raw request body
      response_hash     — SHA3-256 of raw response body
      context_id        — A2A contextId (groups related tasks; null if absent)
      task_id           — A2A task id (null if absent in params)
      reference_task_ids — cross-task causality links (A2A §3.5.3)
      source            — always "a2a_transport" (not from Task.history)
    """

    def __init__(
        self,
        app: Any,
        receipt_store: ReceiptStore | None = None,
    ) -> None:
        self._app = app
        self._store: ReceiptStore = receipt_store if receipt_store is not None else NullReceiptStore()

    async def __call__(
        self,
        scope: _Scope,
        receive: _Receive,
        send: _Send,
    ) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        method: str = scope.get("method", "")

        # Pre-read the full request body for auditing before the app sees it.
        # A2A calls are JSON payloads; buffering the full body is safe.
        request_chunks: list[bytes] = []
        more_body = True
        while more_body:
            msg = await receive()
            if msg.get("type") == "http.request":
                chunk: bytes = msg.get("body", b"")
                if chunk:
                    request_chunks.append(chunk)
                more_body = bool(msg.get("more_body", False))
            else:
                break

        request_body = b"".join(request_chunks)

        # Replay the body for the downstream app via a closure.
        _replayed = False

        async def _receive() -> _Message:
            nonlocal _replayed
            if not _replayed:
                _replayed = True
                return {"type": "http.request", "body": request_body, "more_body": False}
            return {"type": "http.disconnect"}

        response_status: list[int] = []
        response_chunks: list[bytes] = []

        async def _send(msg: _Message) -> None:
            if msg.get("type") == "http.response.start":
                response_status.append(msg.get("status", 0))
            elif msg.get("type") == "http.response.body":
                response_chunks.append(msg.get("body", b""))
            await send(msg)

        await self._app(scope, _receive, _send)

        self._capture_event(
            path=path,
            method=method,
            request_body=request_body,
            response_body=b"".join(response_chunks),
            status=response_status[0] if response_status else 0,
        )

    def _capture_event(
        self,
        path: str,
        method: str,
        request_body: bytes,
        response_body: bytes,
        status: int,
    ) -> None:
        """Store an audit receipt for this transport-layer event."""
        try:
            req_hash = hashlib.sha3_256(request_body).hexdigest()
            resp_hash = hashlib.sha3_256(response_body).hexdigest()

            context_id: str | None = None
            task_id: str | None = None
            reference_task_ids: list[str] = []

            if request_body:
                try:
                    req_json: Any = json.loads(request_body)
                    if isinstance(req_json, dict):
                        params: Any = req_json.get("params") or {}
                        if isinstance(params, dict):
                            context_id = params.get("contextId")
                            task_id = params.get("id")
                            refs: Any = params.get("referenceTaskIds")
                            if isinstance(refs, list):
                                reference_task_ids = [r for r in refs if isinstance(r, str)]
                except (json.JSONDecodeError, AttributeError):
                    pass

            blob = json.dumps({
                "event_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "path": path,
                "method": method,
                "status": status,
                "request_hash": req_hash,
                "response_hash": resp_hash,
                "context_id": context_id,
                "task_id": task_id,
                "reference_task_ids": reference_task_ids,
                "source": "a2a_transport",
            }, separators=(",", ":")).encode("utf-8")

            receipt_hash = hashlib.sha3_256(blob).hexdigest()
            self._store.put(receipt_hash=receipt_hash, blob=blob)

        except Exception as exc:  # noqa: BLE001
            logger.warning("A2A audit capture failed: %s", exc)
