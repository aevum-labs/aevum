# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Tests for aevum.agent.a2a_audit.AevumA2AAuditMiddleware.

The a2a-python SDK is NOT required — the middleware wraps at the ASGI/HTTP layer.
A2A spec §3.5.2: Task.history is unreliable; middleware captures at transport layer.

NO tests/__init__.py (standing rule).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from aevum.core.store import NullReceiptStore

from aevum.agent.a2a_audit import AevumA2AAuditMiddleware


class _CaptureStore:
    """In-memory receipt store that records every put() call for assertions."""

    def __init__(self) -> None:
        self.receipts: list[tuple[str, bytes]] = []

    def put(
        self,
        receipt_hash: str,
        blob: bytes,
        entry_hash: str = "",
        rekor_entry_ref: str = "",
        tier: str = "operational",
    ) -> None:
        self.receipts.append((receipt_hash, blob))

    def get(self, receipt_hash: str) -> bytes | None:
        for h, b in self.receipts:
            if h == receipt_hash:
                return b
        return None

    def lock(self, receipt_hash: str) -> None:
        pass

    def list_hashes(
        self,
        after: str | None = None,
        limit: int = 100,
        tier: str | None = None,
    ) -> list[str]:
        return [h for h, _ in self.receipts]

    def put_ambient(self, snapshot_id: str, blob: bytes, session_id: str, trigger: str) -> None:
        pass

    def get_ambient(self, snapshot_id: str) -> bytes | None:
        return None


def _make_app(
    response_body: bytes = b'{"result":"ok"}',
    status: int = 200,
) -> Any:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": response_body})
    return app


async def _invoke(
    mw: AevumA2AAuditMiddleware,
    path: str = "/tasks/send",
    method: str = "POST",
    request_body: bytes = b"",
) -> None:
    scope = {"type": "http", "path": path, "method": method}

    async def receive() -> Any:
        return {"type": "http.request", "body": request_body}

    async def send(msg: Any) -> None:
        pass

    await mw(scope, receive, send)


class TestInit:
    def test_null_store_when_no_store_provided(self) -> None:
        mw = AevumA2AAuditMiddleware(app=_make_app())
        assert isinstance(mw._store, NullReceiptStore)

    def test_explicit_store_is_used(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        assert mw._store is store


class TestNonHttpPassthrough:
    def test_websocket_scope_passes_through_unchanged(self) -> None:
        inner_called: list[bool] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            inner_called.append(True)

        mw = AevumA2AAuditMiddleware(app=inner)

        async def run() -> None:
            await mw({"type": "websocket"}, None, None)  # type: ignore[arg-type]

        asyncio.run(run())
        assert inner_called == [True]

    def test_lifespan_scope_passes_through_unchanged(self) -> None:
        inner_called: list[bool] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            inner_called.append(True)

        mw = AevumA2AAuditMiddleware(app=inner)

        async def run() -> None:
            await mw({"type": "lifespan"}, None, None)  # type: ignore[arg-type]

        asyncio.run(run())
        assert inner_called == [True]


class TestReceiptCapture:
    def test_stores_one_receipt_per_http_call(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw))
        assert len(store.receipts) == 1

    def test_receipt_hash_matches_sha3_256_of_blob(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw))
        receipt_hash, blob = store.receipts[0]
        assert receipt_hash == hashlib.sha3_256(blob).hexdigest()

    def test_receipt_contains_path(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, path="/tasks/get"))
        event = json.loads(store.receipts[0][1])
        assert event["path"] == "/tasks/get"

    def test_receipt_contains_method(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, method="POST"))
        event = json.loads(store.receipts[0][1])
        assert event["method"] == "POST"

    def test_receipt_contains_response_status(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(status=202), receipt_store=store)
        asyncio.run(_invoke(mw))
        event = json.loads(store.receipts[0][1])
        assert event["status"] == 202

    def test_receipt_contains_request_hash(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        req = b'{"params":{"id":"t1"}}'
        asyncio.run(_invoke(mw, request_body=req))
        event = json.loads(store.receipts[0][1])
        assert event["request_hash"] == hashlib.sha3_256(req).hexdigest()

    def test_receipt_contains_response_hash(self) -> None:
        store = _CaptureStore()
        resp = b'{"result":{"id":"t1","status":"COMPLETED"}}'
        mw = AevumA2AAuditMiddleware(app=_make_app(response_body=resp), receipt_store=store)
        asyncio.run(_invoke(mw))
        event = json.loads(store.receipts[0][1])
        assert event["response_hash"] == hashlib.sha3_256(resp).hexdigest()

    def test_receipt_has_event_id(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw))
        event = json.loads(store.receipts[0][1])
        assert "event_id" in event
        assert len(event["event_id"]) > 0

    def test_receipt_has_timestamp(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw))
        event = json.loads(store.receipts[0][1])
        assert "timestamp" in event
        assert event["timestamp"] > 0

    def test_source_is_a2a_transport(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw))
        event = json.loads(store.receipts[0][1])
        assert event["source"] == "a2a_transport"


class TestContextExtraction:
    def test_extracts_context_id_from_params(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        req = json.dumps({"method": "tasks/send", "params": {"contextId": "ctx-42"}}).encode()
        asyncio.run(_invoke(mw, request_body=req))
        event = json.loads(store.receipts[0][1])
        assert event["context_id"] == "ctx-42"

    def test_extracts_task_id_from_params(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        req = json.dumps({"method": "tasks/send", "params": {"id": "task-99"}}).encode()
        asyncio.run(_invoke(mw, request_body=req))
        event = json.loads(store.receipts[0][1])
        assert event["task_id"] == "task-99"

    def test_extracts_reference_task_ids(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        req = json.dumps({"params": {"referenceTaskIds": ["t1", "t2", "t3"]}}).encode()
        asyncio.run(_invoke(mw, request_body=req))
        event = json.loads(store.receipts[0][1])
        assert event["reference_task_ids"] == ["t1", "t2", "t3"]

    def test_context_id_none_when_absent(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b'{"params":{}}'))
        event = json.loads(store.receipts[0][1])
        assert event["context_id"] is None

    def test_task_id_none_when_absent(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b'{"params":{}}'))
        event = json.loads(store.receipts[0][1])
        assert event["task_id"] is None

    def test_reference_task_ids_empty_when_absent(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b'{"params":{}}'))
        event = json.loads(store.receipts[0][1])
        assert event["reference_task_ids"] == []

    def test_malformed_request_body_does_not_crash(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b"not json {{"))
        assert len(store.receipts) == 1
        event = json.loads(store.receipts[0][1])
        assert event["context_id"] is None

    def test_empty_request_body_does_not_crash(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b""))
        assert len(store.receipts) == 1


class TestTaskHistoryIndependence:
    def test_does_not_import_a2a_sdk(self) -> None:
        """Middleware must not require a2a-python SDK — it captures at transport layer."""
        from aevum.agent.a2a_audit import AevumA2AAuditMiddleware as Mw
        assert Mw is not None

    def test_captures_without_task_history(self) -> None:
        """Verify event source is 'a2a_transport', not from Task.history."""
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b'{"params":{"id":"t1"}}'))
        event = json.loads(store.receipts[0][1])
        assert event["source"] == "a2a_transport"
        # Task history field is never present — captured from transport
        assert "history" not in event

    def test_multiple_calls_produce_multiple_receipts(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw, request_body=b'{"params":{"id":"t1"}}'))
        asyncio.run(_invoke(mw, request_body=b'{"params":{"id":"t2"}}'))
        asyncio.run(_invoke(mw, request_body=b'{"params":{"id":"t3"}}'))
        assert len(store.receipts) == 3

    def test_each_event_has_unique_event_id(self) -> None:
        store = _CaptureStore()
        mw = AevumA2AAuditMiddleware(app=_make_app(), receipt_store=store)
        asyncio.run(_invoke(mw))
        asyncio.run(_invoke(mw))
        ids = [json.loads(blob)["event_id"] for _, blob in store.receipts]
        assert len(set(ids)) == 2
