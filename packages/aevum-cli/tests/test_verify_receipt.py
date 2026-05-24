"""
Tests for aevum verify-receipt CLI command.
Uses typer's CliRunner.
"""
from __future__ import annotations

import re
from pathlib import Path

import cbor2
import nacl.signing
import pytest
from typer.testing import CliRunner

from aevum.cli.app import app

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*[mGKH]")


def plain(text: str) -> str:
    return _ANSI.sub("", text)


def _make_valid_receipt_file(tmp_path: Path) -> tuple[Path, nacl.signing.SigningKey]:
    """Create a valid COSE_Sign1 receipt file and return its path + signing key."""
    from aevum.core.audit.event import AuditEvent
    from aevum.core.receipt import AevumReceipt
    from aevum.publish.encoder import ReceiptEncoder

    signer_key = nacl.signing.SigningKey.generate()

    class _NaClSigner:
        key_id = "test-verify-key"
        provenance = "test"
        def sign(self, digest: bytes) -> bytes:
            return bytes(signer_key.sign(digest).signature)
        def public_key_bytes(self) -> bytes:
            return bytes(signer_key.verify_key)

    encoder = ReceiptEncoder(signer=_NaClSigner(), dev_mode=True)  # type: ignore[arg-type]
    event = AuditEvent(
        event_id="ev-cli-test-01",
        episode_id="ep-cli-01",
        sequence=1,
        event_type="cli.test.action",
        schema_version="1.0",
        valid_from="2026-05-24T00:00:00+00:00",
        valid_to=None,
        system_time=0,
        causation_id=None,
        correlation_id=None,
        actor="cli-test-agent",
        trace_id=None,
        span_id=None,
        payload={},
        payload_hash=AuditEvent.hash_payload({}),
        prior_hash="c" * 64,
        signature="dGVzdA",
        signer_key_id="test-key",
    )
    receipt = AevumReceipt.from_sigchain_event(event)
    receipt_cbor = encoder.encode(receipt)

    receipt_file = tmp_path / "test_receipt.cose"
    receipt_file.write_bytes(receipt_cbor)

    pub_key_path = tmp_path / ".aevum" / "ed25519.pub"
    pub_key_path.parent.mkdir(parents=True, exist_ok=True)
    pub_key_path.write_bytes(bytes(signer_key.verify_key))

    return receipt_file, signer_key


def test_verify_receipt_help() -> None:
    result = runner.invoke(app, ["verify-receipt", "--help"])
    assert result.exit_code == 0
    assert "receipt" in plain(result.output).lower()


def test_verify_receipt_file_not_found(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify-receipt", str(tmp_path / "nonexistent.cose")])
    assert result.exit_code == 1
    assert "not found" in plain(result.output + (result.stdout or "")).lower()


def test_verify_receipt_invalid_cbor(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.cose"
    bad_file.write_bytes(b"\xff\xff\xff not valid cbor")
    result = runner.invoke(app, ["verify-receipt", str(bad_file)])
    assert result.exit_code == 1


def test_verify_receipt_wrong_algorithm(tmp_path: Path) -> None:
    protected_bstr = cbor2.dumps({1: -7, 3: "application/aevum-receipt+cbor", 4: b"kid"})
    payload = cbor2.dumps({"action": "test"})
    cose = [protected_bstr, {}, payload, b"sig"]
    bad_file = tmp_path / "wrong_alg.cose"
    bad_file.write_bytes(cbor2.dumps(cose))
    result = runner.invoke(app, ["verify-receipt", str(bad_file)])
    assert result.exit_code == 2
    assert "UNSUPPORTED ALGORITHM" in plain(result.output + (result.stdout or ""))


def test_verify_receipt_no_public_key_shows_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aevum.core.audit.event import AuditEvent
    from aevum.core.audit.signer import InProcessSigner
    from aevum.core.receipt import AevumReceipt
    from aevum.publish.encoder import ReceiptEncoder

    monkeypatch.setenv("HOME", str(tmp_path))
    signer = InProcessSigner()
    encoder = ReceiptEncoder(signer=signer, dev_mode=True)
    event = AuditEvent(
        event_id="ev-warn-01",
        episode_id="ep-warn-01",
        sequence=1,
        event_type="warn.test",
        schema_version="1.0",
        valid_from="2026-05-24T00:00:00+00:00",
        valid_to=None,
        system_time=0,
        causation_id=None,
        correlation_id=None,
        actor="warn-agent",
        trace_id=None,
        span_id=None,
        payload={},
        payload_hash=AuditEvent.hash_payload({}),
        prior_hash="d" * 64,
        signature="dGVzdA",
        signer_key_id="test-key",
    )
    receipt = AevumReceipt.from_sigchain_event(event)
    receipt_cbor = encoder.encode(receipt)
    receipt_file = tmp_path / "no_key_receipt.cose"
    receipt_file.write_bytes(receipt_cbor)

    result = runner.invoke(app, ["verify-receipt", str(receipt_file)])
    output = plain(result.output + (result.stdout or ""))
    assert "WARNING" in output or "unverified" in output.lower()
