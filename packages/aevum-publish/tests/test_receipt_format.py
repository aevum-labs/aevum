# SPDX-License-Identifier: Apache-2.0
"""
Tests for COSE_Sign1 receipt format — public API surface via aevum.publish.receipt.

No network calls. All tests use InProcessSigner (dev_mode=True).
Signature verification uses ephemeral key pairs.
"""
from __future__ import annotations

import cbor2
import nacl.signing
import pytest
from aevum.core.audit.signer import InProcessSigner

from aevum.publish.backends import NullBackend, ScittTsBackend
from aevum.publish.receipt import AevumReceipt, ReceiptEncoder


def _make_receipt(**kwargs: object) -> AevumReceipt:
    defaults: dict[str, object] = {
        "sigchain_entry_hash": "a" * 64,
        "action": "maintenance.scan",
        "principal": "github_actions",
        "prior_hash": "b" * 64,
        "occurred_at": "2026-06-05T10:00:00+00:00",
        "agent_id": "test-agent",
        "sequence": 1,
    }
    defaults.update(kwargs)
    return AevumReceipt.model_validate(defaults)


def _make_encoder() -> tuple[ReceiptEncoder, nacl.signing.VerifyKey]:
    """Return (encoder, verify_key) using an ephemeral InProcessSigner."""
    signer = InProcessSigner()
    encoder = ReceiptEncoder(signer=signer, dev_mode=True)
    verify_key = nacl.signing.VerifyKey(signer.public_key_bytes())
    return encoder, verify_key


# ── Encoding tests ────────────────────────────────────────────


def test_encode_returns_bytes() -> None:
    encoder, _ = _make_encoder()
    result = encoder.encode(_make_receipt())
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_encode_is_valid_cbor() -> None:
    encoder, _ = _make_encoder()
    result = encoder.encode(_make_receipt())
    decoded = cbor2.loads(result)
    assert isinstance(decoded, list)
    assert len(decoded) == 4


def test_protected_header_contains_eddsa_alg() -> None:
    """alg MUST be -8 (EdDSA), never -7 (ES256)."""
    encoder, _ = _make_encoder()
    result = encoder.encode(_make_receipt())
    tag = cbor2.loads(result)
    protected = cbor2.loads(tag[0])
    assert protected[1] == -8, f"Expected alg=-8 (EdDSA), got alg={protected[1]}"


def test_protected_header_contains_kid() -> None:
    encoder, _ = _make_encoder()
    result = encoder.encode(_make_receipt())
    protected = cbor2.loads(cbor2.loads(result)[0])
    assert protected[4] == b"aevum-issuer-v1"


def test_signature_is_64_bytes() -> None:
    """Ed25519 signatures are always 64 bytes."""
    encoder, _ = _make_encoder()
    result = encoder.encode(_make_receipt())
    signature = cbor2.loads(result)[3]
    assert len(bytes(signature)) == 64


# ── Round-trip verification tests ─────────────────────────────


def test_decode_and_verify_roundtrip() -> None:
    encoder, vk = _make_encoder()
    receipt = _make_receipt(action="docs.published")
    cose_bytes = encoder.encode(receipt)
    decoded = ReceiptEncoder.decode_and_verify(cose_bytes, vk)
    assert decoded.action == "docs.published"
    assert decoded.principal == "github_actions"


def test_decode_detects_tampered_payload() -> None:
    """Modifying the payload must fail signature verification."""
    from nacl.exceptions import BadSignatureError

    encoder, vk = _make_encoder()
    cose_bytes = encoder.encode(_make_receipt())
    original = cbor2.loads(cose_bytes)
    tampered_raw = cbor2.dumps([
        original[0],              # protected (unchanged)
        original[1],              # unprotected (unchanged)
        b"tampered payload data", # ← changed
        original[3],              # signature (now invalid)
    ])
    with pytest.raises(BadSignatureError):
        ReceiptEncoder.decode_and_verify(tampered_raw, vk)


def test_decode_detects_wrong_key() -> None:
    """Verifying with a different key must fail."""
    from nacl.exceptions import BadSignatureError

    encoder, _ = _make_encoder()
    cose_bytes = encoder.encode(_make_receipt())
    wrong_vk = nacl.signing.VerifyKey(InProcessSigner().public_key_bytes())
    with pytest.raises(BadSignatureError):
        ReceiptEncoder.decode_and_verify(cose_bytes, wrong_vk)


def test_decode_rejects_non_cose_array() -> None:
    garbage = cbor2.dumps({"not": "cose"})
    _, vk = _make_encoder()
    with pytest.raises(ValueError, match="4-element"):
        ReceiptEncoder.decode_and_verify(garbage, vk)


# ── AevumReceipt CBOR serialisation ──────────────────────────


def test_receipt_cbor_roundtrip() -> None:
    receipt = _make_receipt(consent_token_id="tok-abc")
    cbor_bytes = receipt.to_cbor_payload()
    decoded = cbor2.loads(cbor_bytes)
    assert decoded["consent_token_id"] == "tok-abc"
    assert decoded["action"] == "maintenance.scan"


def test_receipt_cbor_keys_sorted() -> None:
    receipt = _make_receipt()
    decoded = cbor2.loads(receipt.to_cbor_payload())
    keys = list(decoded.keys())
    assert keys == sorted(keys)


# ── Backend tests ─────────────────────────────────────────────


def test_null_backend_returns_string() -> None:
    encoder, _ = _make_encoder()
    cose_bytes = encoder.encode(_make_receipt())
    backend = NullBackend()
    entry_id = backend.submit(cose_bytes)
    assert isinstance(entry_id, str)
    assert len(entry_id) > 0


def test_null_backend_is_deterministic() -> None:
    backend = NullBackend()
    data = b"test-receipt"
    assert backend.submit(data) == backend.submit(data)


def test_scitt_backend_raises_not_implemented() -> None:
    backend = ScittTsBackend(scrapi_url="https://ts.example.com")
    encoder, _ = _make_encoder()
    cose_bytes = encoder.encode(_make_receipt())
    with pytest.raises(NotImplementedError, match="ScrAPI"):
        backend.submit(cose_bytes)


# ── TST disabled by default ───────────────────────────────────


def test_no_tst_in_unprotected_header_by_default() -> None:
    """TST must not appear unless TSA client is configured and not dev_mode."""
    encoder, _ = _make_encoder()
    cose_bytes = encoder.encode(_make_receipt())
    unprotected = cbor2.loads(cose_bytes)[1]
    assert 9 not in unprotected
