# SPDX-License-Identifier: Apache-2.0
"""Coverage for Sigchain.new_event()'s optional, non-blocking pipeline stages
(receipt_encoder, receipt_store, exceedance_detector) and capture_ambient_context().

All four stages are duck-typed (no isinstance checks in sigchain.py), so plain
stub classes implementing only the methods actually called are sufficient —
no oqs/liboqs dependency needed for any test in this file.
"""

from __future__ import annotations

import cbor2
from aevum.publish.encoder import ReceiptEncoder

from aevum.core.ambient import (
    TRIGGER_INCIDENT_LOCK,
    TRIGGER_PERIODIC,
    TRIGGER_STATE_CHANGE,
    AmbientContextEncoder,
)
from aevum.core.audit.sigchain import Sigchain
from aevum.core.audit.signer import InProcessSigner


class _StubReceiptEncoder:
    """Duck-typed receipt_encoder stub: only .encode() is ever called."""

    def __init__(self, output: bytes | None = None, raise_exc: Exception | None = None) -> None:
        self._output = output
        self._raise_exc = raise_exc

    def encode(self, receipt: object) -> bytes:
        if self._raise_exc is not None:
            raise self._raise_exc
        assert self._output is not None
        return self._output


class _RecordingReceiptStore:
    """Duck-typed receipt_store stub recording put()/put_ambient() calls."""

    def __init__(self) -> None:
        self.put_calls: list[str] = []
        self.put_ambient_calls: list[str] = []

    def put(
        self,
        receipt_hash: str,
        blob: bytes,
        entry_hash: str = "",
        rekor_entry_ref: str = "",
        tier: str = "operational",
    ) -> None:
        self.put_calls.append(receipt_hash)

    def get(self, receipt_hash: str) -> bytes | None:
        return None

    def lock(self, receipt_hash: str) -> None:
        pass

    def list_hashes(
        self, after: str | None = None, limit: int = 100, tier: str | None = None
    ) -> list[str]:
        return []

    def put_ambient(self, snapshot_id: str, blob: bytes, session_id: str, trigger: str) -> None:
        self.put_ambient_calls.append(snapshot_id)

    def get_ambient(self, snapshot_id: str) -> bytes | None:
        return None


class _ExplodingPutReceiptStore(_RecordingReceiptStore):
    def put(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("receipt store unavailable")


class _ExplodingPutAmbientReceiptStore(_RecordingReceiptStore):
    def put_ambient(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("ambient store unavailable")


class _RecordingExceedanceDetector:
    """Duck-typed exceedance_detector stub: only .process() is ever called."""

    def __init__(self) -> None:
        self.processed: list[object] = []

    def process(self, receipt: object) -> list[object]:
        self.processed.append(receipt)
        return []


# ── receipt_encoder block (sigchain.py new_event, lines ~394-402) ──────────────────


def test_receipt_encoder_attaches_cbor_to_event() -> None:
    chain = Sigchain(receipt_encoder=_StubReceiptEncoder(output=b"\x01\x02\x03"))
    event = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert event.receipt_cbor == b"\x01\x02\x03"


def test_receipt_encoder_failure_is_non_blocking() -> None:
    chain = Sigchain(receipt_encoder=_StubReceiptEncoder(raise_exc=RuntimeError("encode boom")))
    event = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert event.receipt_cbor is None


# ── receipt_store block (sigchain.py new_event, lines ~405-434) ────────────────────


def test_receipt_store_put_called_with_real_receipt() -> None:
    """Success path: a real COSE_Sign1 receipt decodes cleanly through the inner
    escalation check (which evaluates to no-escalation and stores via store.put())."""
    signer = InProcessSigner()
    store = _RecordingReceiptStore()
    chain = Sigchain(signer=signer, receipt_encoder=ReceiptEncoder(signer=signer), receipt_store=store)
    event = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert event.receipt_cbor is not None
    assert len(store.put_calls) == 1


def test_receipt_store_escalation_check_exception_is_non_blocking() -> None:
    """A receipt_cbor that decodes as valid CBOR but isn't a 4-element COSE_Sign1
    array (cose[2] missing) makes the inner escalation-check try block raise —
    store.put() must already have succeeded, and the outer call must not blow up."""
    store = _RecordingReceiptStore()
    chain = Sigchain(
        receipt_encoder=_StubReceiptEncoder(output=cbor2.dumps([1, 2])),
        receipt_store=store,
    )
    event = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert event.receipt_cbor is not None
    assert len(store.put_calls) == 1


def test_receipt_store_put_failure_is_non_blocking() -> None:
    chain = Sigchain(
        receipt_encoder=_StubReceiptEncoder(output=b"\x01\x02\x03"),
        receipt_store=_ExplodingPutReceiptStore(),
    )
    event = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert event.receipt_cbor == b"\x01\x02\x03"


# ── exceedance_detector block (sigchain.py new_event, lines ~437-446) ──────────────


def test_exceedance_detector_called_when_receipt_cbor_present() -> None:
    signer = InProcessSigner()
    detector = _RecordingExceedanceDetector()
    chain = Sigchain(
        signer=signer,
        receipt_encoder=ReceiptEncoder(signer=signer),
        exceedance_detector=detector,
    )
    chain.new_event(event_type="test.e", payload={}, actor="a")
    assert len(detector.processed) == 1


def test_exceedance_detector_failure_is_non_blocking() -> None:
    detector = _RecordingExceedanceDetector()
    chain = Sigchain(
        receipt_encoder=_StubReceiptEncoder(output=cbor2.dumps([1, 2])),
        exceedance_detector=detector,
    )
    event = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert event.receipt_cbor is not None
    assert detector.processed == []


# ── capture_ambient_context() (sigchain.py, lines ~548-630) ────────────────────────


def test_capture_ambient_context_returns_none_without_encoder() -> None:
    chain = Sigchain()
    result = chain.capture_ambient_context(trigger=TRIGGER_STATE_CHANGE, session_id="s1")
    assert result is None


def test_capture_ambient_context_builds_snapshot_without_receipt_store() -> None:
    signer = InProcessSigner()
    chain = Sigchain(signer=signer, ambient_encoder=AmbientContextEncoder(signer=signer))
    snapshot = chain.capture_ambient_context(
        trigger=TRIGGER_STATE_CHANGE,
        session_id="session-1",
        model_identity_hash="m1",
        policy_version="p1",
        tool_allowlist_hash="t1",
    )
    assert snapshot is not None
    assert snapshot.trigger == TRIGGER_STATE_CHANGE
    assert snapshot.session_id == "session-1"
    assert snapshot.model_identity_hash == "m1"
    assert snapshot.system_state_hash != "UNKNOWN"


def test_capture_ambient_context_stores_via_receipt_store() -> None:
    signer = InProcessSigner()
    store = _RecordingReceiptStore()
    chain = Sigchain(
        signer=signer,
        ambient_encoder=AmbientContextEncoder(signer=signer),
        receipt_store=store,
    )
    snapshot = chain.capture_ambient_context(trigger=TRIGGER_PERIODIC, session_id="s2")
    assert snapshot is not None
    assert len(store.put_ambient_calls) == 1


def test_capture_ambient_context_storage_failure_is_non_blocking() -> None:
    signer = InProcessSigner()
    chain = Sigchain(
        signer=signer,
        ambient_encoder=AmbientContextEncoder(signer=signer),
        receipt_store=_ExplodingPutAmbientReceiptStore(),
    )
    snapshot = chain.capture_ambient_context(trigger=TRIGGER_INCIDENT_LOCK, session_id="s3")
    assert snapshot is not None
