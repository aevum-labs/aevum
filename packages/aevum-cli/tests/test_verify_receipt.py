# SPDX-License-Identifier: Apache-2.0
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


class _RealTsaFakeClient:
    """A TSAClient-like object that issues a real `openssl ts` token over
    whatever bytes the encoder passes to .timestamp() (i.e. the signature
    bytes, per CTT). No network — mirrors the mock-TSA approach used in
    aevum-verify/tests/test_receipt_tsa.py."""

    def __init__(self, tsa_dir: Path) -> None:
        self._dir = tsa_dir

    def timestamp(self, data: bytes) -> object:
        import subprocess

        from aevum.core.tsa import TSAToken

        d = self._dir
        data_path = d / "data.bin"
        data_path.write_bytes(data)
        subprocess.run(
            ["openssl", "ts", "-query", "-data", str(data_path),
             "-no_nonce", "-sha256", "-out", str(d / "req.tsq")],
            capture_output=True, check=True,
        )
        r = subprocess.run(
            ["openssl", "ts", "-reply", "-config", str(d / "tsa.conf"),
             "-queryfile", str(d / "req.tsq"), "-out", str(d / "resp.tsr")],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, f"openssl ts -reply failed: {r.stderr}"
        return TSAToken(tsa_url="https://tsa.invalid", token_bytes=(d / "resp.tsr").read_bytes())


def _make_mock_tsa_dir(tmp_path: Path) -> Path:
    """Self-signed TSA CA + openssl `ts` config, no network."""
    import subprocess

    d = tmp_path / "tsa"
    d.mkdir()
    subprocess.run(
        ["openssl", "genrsa", "-out", str(d / "tsa.key"), "2048"],
        capture_output=True, check=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", str(d / "tsa.key"),
            "-out", str(d / "tsa.crt"),
            "-subj", "/CN=Mock CLI TSA",
            "-days", "3650",
            "-addext", "extendedKeyUsage=critical,timeStamping",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ],
        capture_output=True, check=True,
    )
    (d / "serial").write_text("01\n")
    (d / "tsa.conf").write_text(
        "[ tsa ]\ndefault_tsa = cfg\n"
        "[ cfg ]\n"
        f"dir = {d}\n"
        f"serial = {d}/serial\n"
        "crypto_device = builtin\n"
        f"signer_cert = {d}/tsa.crt\n"
        f"signer_key = {d}/tsa.key\n"
        "signer_digest = sha256\n"
        "default_policy = 1.2.3.4.5.6.7.8\n"
        "digests = sha256\n"
        "accuracy = secs:1\n"
        "ordering = no\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n"
    )
    return d


def _make_receipt_with_ctt(tmp_path: Path) -> tuple[Path, Path]:
    """Encode a receipt with a real CTT token; return (receipt_file, tsa_cert_pem_path)."""
    from aevum.core.audit.event import AuditEvent
    from aevum.core.audit.signer import InProcessSigner
    from aevum.core.receipt import AevumReceipt
    from aevum.publish.encoder import ReceiptEncoder

    tsa_dir = _make_mock_tsa_dir(tmp_path)
    signer = InProcessSigner()
    encoder = ReceiptEncoder(signer=signer, tsa_client=_RealTsaFakeClient(tsa_dir), dev_mode=False)  # type: ignore[arg-type]
    event = AuditEvent(
        event_id="ev-ctt-01",
        episode_id="ep-ctt-01",
        sequence=1,
        event_type="ctt.test",
        schema_version="1.0",
        valid_from="2026-05-24T00:00:00+00:00",
        valid_to=None,
        system_time=0,
        causation_id=None,
        correlation_id=None,
        actor="ctt-agent",
        trace_id=None,
        span_id=None,
        payload={},
        payload_hash=AuditEvent.hash_payload({}),
        prior_hash="e" * 64,
        signature="dGVzdA",
        signer_key_id="test-key",
    )
    receipt = AevumReceipt.from_sigchain_event(event)
    receipt_cbor = encoder.encode(receipt)

    receipt_file = tmp_path / "ctt_receipt.cose"
    receipt_file.write_bytes(receipt_cbor)

    aevum_dir = tmp_path / ".aevum"
    aevum_dir.mkdir(parents=True, exist_ok=True)
    (aevum_dir / "ed25519.pub").write_bytes(signer.public_key_bytes())

    return receipt_file, tsa_dir / "tsa.crt"


def test_verify_receipt_ctt_verified_with_pinned_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    receipt_file, tsa_cert_path = _make_receipt_with_ctt(tmp_path)
    (tmp_path / ".aevum" / "tsa-root.pem").write_bytes(tsa_cert_path.read_bytes())

    result = runner.invoke(app, ["verify-receipt", str(receipt_file)])
    output = plain(result.output + (result.stdout or ""))
    assert "verified" in output.lower().split("tsa timestamp:")[1].splitlines()[0]
    assert result.exit_code == 0


def test_verify_receipt_ctt_present_but_unverified_without_root_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    receipt_file, _tsa_cert_path = _make_receipt_with_ctt(tmp_path)
    # No ~/.aevum/tsa-root.pem written — presence reported, not verified.

    result = runner.invoke(app, ["verify-receipt", str(receipt_file)])
    output = plain(result.output + (result.stdout or ""))
    assert "unverified" in output.lower()
    assert "RFC 3161 token" in output


def test_verify_receipt_ctt_failed_with_wrong_root_cert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    monkeypatch.setenv("HOME", str(tmp_path))
    receipt_file, _tsa_cert_path = _make_receipt_with_ctt(tmp_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CA")])
    wrong_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (tmp_path / ".aevum" / "tsa-root.pem").write_bytes(wrong_cert.public_bytes(serialization.Encoding.PEM))

    result = runner.invoke(app, ["verify-receipt", str(receipt_file)])
    output = plain(result.output + (result.stdout or ""))
    assert "FAILED" in output.split("TSA timestamp:")[1].splitlines()[0]


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
