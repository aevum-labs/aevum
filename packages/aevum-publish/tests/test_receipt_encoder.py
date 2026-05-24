"""
Tests for ReceiptEncoder, AevumReceipt, and TransparencyBackend.
"""
from __future__ import annotations

import cbor2
import pytest
from aevum.core.audit.event import AuditEvent
from aevum.core.audit.signer import InProcessSigner
from aevum.core.receipt import AevumReceipt

from aevum.publish.backends import NullBackend, ScittTsBackend, TransparencyBackend
from aevum.publish.encoder import ReceiptEncoder


def _make_event(sequence: int = 1, event_type: str = "test.action") -> AuditEvent:
    return AuditEvent(
        event_id=f"evt-{sequence:04d}",
        episode_id="ep-test",
        sequence=sequence,
        event_type=event_type,
        schema_version="1.0",
        valid_from="2026-05-24T00:00:00+00:00",
        valid_to=None,
        system_time=0,
        causation_id=None,
        correlation_id=None,
        actor="test-agent",
        trace_id=None,
        span_id=None,
        payload={"k": "v"},
        payload_hash=AuditEvent.hash_payload({"k": "v"}),
        prior_hash="a" * 64,
        signature="dGVzdA",
        signer_key_id="test-key",
    )


class TestAevumReceipt:
    def test_from_sigchain_event_defaults(self) -> None:
        event = _make_event()
        receipt = AevumReceipt.from_sigchain_event(event)
        assert receipt.action == "test.action"
        assert receipt.principal == "test-agent"
        assert receipt.sequence == 1
        assert receipt.model_identity_hash == "UNKNOWN"
        assert receipt.retrieval_corpus_ver == "NONE"
        assert receipt.handoff_type is None

    def test_from_sigchain_event_with_kwargs(self) -> None:
        event = _make_event()
        receipt = AevumReceipt.from_sigchain_event(
            event,
            model_identity_hash="abc123",
            policy_version="v2",
            handoff_type="TRANSITION_DEMAND",
        )
        assert receipt.model_identity_hash == "abc123"
        assert receipt.policy_version == "v2"
        assert receipt.handoff_type == "TRANSITION_DEMAND"

    def test_to_cbor_payload_round_trip(self) -> None:
        event = _make_event()
        receipt = AevumReceipt.from_sigchain_event(event)
        cbor_bytes = receipt.to_cbor_payload()
        decoded = cbor2.loads(cbor_bytes)
        assert decoded["action"] == "test.action"
        assert decoded["sequence"] == 1
        assert "model_identity_hash" in decoded
        assert "prompt_hash" in decoded
        assert "retrieval_corpus_ver" in decoded
        assert "policy_version" in decoded
        assert "tool_allowlist_hash" in decoded

    def test_to_cbor_payload_sorted_keys(self) -> None:
        event = _make_event()
        receipt = AevumReceipt.from_sigchain_event(event)
        cbor_bytes = receipt.to_cbor_payload()
        decoded = cbor2.loads(cbor_bytes)
        keys = list(decoded.keys())
        assert keys == sorted(keys)


class TestReceiptEncoder:
    def test_encode_produces_4_element_array(self) -> None:
        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        receipt = AevumReceipt.from_sigchain_event(_make_event())
        raw = encoder.encode(receipt)
        decoded = cbor2.loads(raw)
        assert isinstance(decoded, list)
        assert len(decoded) == 4

    def test_encode_protected_header_alg_minus_8(self) -> None:
        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        receipt = AevumReceipt.from_sigchain_event(_make_event())
        raw = encoder.encode(receipt)
        decoded = cbor2.loads(raw)
        protected = cbor2.loads(decoded[0])
        assert protected[1] == -8, f"Expected alg=-8, got {protected[1]}"

    def test_encode_protected_header_content_type(self) -> None:
        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        receipt = AevumReceipt.from_sigchain_event(_make_event())
        raw = encoder.encode(receipt)
        decoded = cbor2.loads(raw)
        protected = cbor2.loads(decoded[0])
        assert protected[3] == "application/aevum-receipt+cbor"

    def test_encode_payload_matches_receipt(self) -> None:
        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        receipt = AevumReceipt.from_sigchain_event(_make_event())
        raw = encoder.encode(receipt)
        decoded = cbor2.loads(raw)
        payload_decoded = cbor2.loads(decoded[2])
        assert payload_decoded["action"] == "test.action"

    def test_encode_no_tsa_in_dev_mode(self) -> None:
        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        receipt = AevumReceipt.from_sigchain_event(_make_event())
        raw = encoder.encode(receipt)
        decoded = cbor2.loads(raw)
        unprotected = decoded[1]
        assert 9 not in unprotected

    def test_encode_signature_verifiable(self) -> None:
        import hashlib

        import nacl.signing

        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        receipt = AevumReceipt.from_sigchain_event(_make_event())
        raw = encoder.encode(receipt)
        decoded = cbor2.loads(raw)

        protected_bstr, _unprotected, payload_bstr, sig_bytes = decoded
        sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
        digest = hashlib.sha3_256(sig_structure).digest()

        pub_bytes = signer.public_key_bytes()
        verify_key = nacl.signing.VerifyKey(pub_bytes)
        verify_key.verify(digest, bytes(sig_bytes))

    def test_from_env_dev_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEVUM_DEV", "1")
        encoder = ReceiptEncoder.from_env()
        assert encoder._dev_mode is True
        assert encoder._tsa_client is None

    def test_from_env_production_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEVUM_DEV", raising=False)
        encoder = ReceiptEncoder.from_env()
        assert encoder._dev_mode is False
        assert encoder._tsa_client is not None


class TestTransparencyBackends:
    def test_null_backend_is_deterministic(self) -> None:
        backend = NullBackend()
        receipt_bytes = b"test-receipt-bytes"
        ref1 = backend.submit(receipt_bytes)
        ref2 = backend.submit(receipt_bytes)
        assert ref1 == ref2

    def test_null_backend_different_inputs_differ(self) -> None:
        backend = NullBackend()
        assert backend.submit(b"a") != backend.submit(b"b")

    def test_null_backend_implements_protocol(self) -> None:
        backend = NullBackend()
        assert isinstance(backend, TransparencyBackend)

    def test_scitt_raises_not_implemented(self) -> None:
        backend = ScittTsBackend(scrapi_url="https://example.scitt.invalid")
        with pytest.raises(NotImplementedError, match="ScrAPI"):
            backend.submit(b"receipt")


class TestSigchainReceiptWiring:
    def test_sigchain_without_encoder_no_receipt(self) -> None:
        from aevum.core.audit.sigchain import Sigchain
        chain = Sigchain()
        event = chain.new_event(event_type="test", payload={}, actor="agent-1")
        assert event.receipt_cbor is None

    def test_sigchain_with_encoder_attaches_receipt(self) -> None:
        from aevum.core.audit.sigchain import Sigchain
        signer = InProcessSigner()
        encoder = ReceiptEncoder(signer=signer, dev_mode=True)
        chain = Sigchain(receipt_encoder=encoder)
        event = chain.new_event(event_type="test.op", payload={}, actor="agent-2")
        assert event.receipt_cbor is not None
        decoded = cbor2.loads(event.receipt_cbor)
        assert isinstance(decoded, list)
        assert len(decoded) == 4

    def test_existing_tests_unaffected(self) -> None:
        from aevum.core.audit.sigchain import Sigchain
        chain = Sigchain()
        e1 = chain.new_event(event_type="a", payload={}, actor="x")
        e2 = chain.new_event(event_type="b", payload={}, actor="x")
        assert e1.sequence == 1
        assert e2.sequence == 2
        assert e1.receipt_cbor is None
