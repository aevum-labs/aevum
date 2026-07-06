# SPDX-License-Identifier: Apache-2.0
"""
verify_receipt_tsa — independent CTT (RFC 9921 label 270) validation for
per-entry COSE_Sign1 receipts produced by aevum.publish.encoder.ReceiptEncoder.

Mirrors the mock-TSA approach in test_merkle_sth.py's TestVerifySthTsaFull:
a real self-signed TSA cert + real `openssl ts` response, no network.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import cbor2
import pytest

_COSE_CTT_LABEL = 270


@pytest.fixture(scope="module")
def mock_tsa(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Self-signed TSA cert + a real RFC 3161 token over `signature_bytes`."""
    d = tmp_path_factory.mktemp("receipt-tsa")
    signature_bytes = bytes(range(64))  # stand-in for a 64-byte Ed25519 signature

    subprocess.run(
        ["openssl", "genrsa", "-out", str(d / "tsa.key"), "2048"],
        capture_output=True, check=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", str(d / "tsa.key"),
            "-out", str(d / "tsa.crt"),
            "-subj", "/CN=Mock Receipt TSA",
            "-days", "3650",
            "-addext", "extendedKeyUsage=critical,timeStamping",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ],
        capture_output=True, check=True,
    )

    (d / "serial").write_text("01\n")
    tsa_conf = (
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
    (d / "tsa.conf").write_text(tsa_conf)

    (d / "sig.bin").write_bytes(signature_bytes)
    subprocess.run(
        ["openssl", "ts", "-query", "-data", str(d / "sig.bin"),
         "-no_nonce", "-sha256", "-out", str(d / "req.tsq")],
        capture_output=True, check=True,
    )
    r = subprocess.run(
        ["openssl", "ts", "-reply", "-config", str(d / "tsa.conf"),
         "-queryfile", str(d / "req.tsq"), "-out", str(d / "resp.tsr")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"openssl ts -reply failed: {r.stderr}"

    return {
        "signature_bytes": signature_bytes,
        "tsa_cert_pem": (d / "tsa.crt").read_bytes(),
        "tsa_token_bytes": (d / "resp.tsr").read_bytes(),
    }


def _make_cose(signature_bytes: bytes, unprotected: dict) -> bytes:
    protected_bstr = cbor2.dumps({1: -8, 3: "application/aevum-receipt+cbor"})
    payload_bstr = cbor2.dumps({"action": "test.action"})
    return cbor2.dumps([protected_bstr, unprotected, payload_bstr, signature_bytes])


class TestVerifyReceiptTsa:
    def test_valid_ctt_token_returns_true(self, mock_tsa: dict) -> None:
        from aevum.verify._core import verify_receipt_tsa
        cose_bytes = _make_cose(
            mock_tsa["signature_bytes"],
            {_COSE_CTT_LABEL: mock_tsa["tsa_token_bytes"]},
        )
        assert verify_receipt_tsa(cose_bytes, tsa_root_cert=mock_tsa["tsa_cert_pem"]) is True

    def test_no_ctt_token_returns_none(self, mock_tsa: dict) -> None:
        from aevum.verify._core import verify_receipt_tsa
        cose_bytes = _make_cose(mock_tsa["signature_bytes"], {})
        assert verify_receipt_tsa(cose_bytes, tsa_root_cert=mock_tsa["tsa_cert_pem"]) is None

    def test_tampered_signature_bytes_returns_false(self, mock_tsa: dict) -> None:
        """Token was issued over the original signature bytes; a different
        signature (e.g. re-signed / tampered receipt) must fail imprint check."""
        from aevum.verify._core import verify_receipt_tsa
        tampered_signature = bytes([0xFF]) + mock_tsa["signature_bytes"][1:]
        cose_bytes = _make_cose(
            tampered_signature,
            {_COSE_CTT_LABEL: mock_tsa["tsa_token_bytes"]},
        )
        assert verify_receipt_tsa(cose_bytes, tsa_root_cert=mock_tsa["tsa_cert_pem"]) is False

    def test_wrong_anchor_cert_returns_false(self, mock_tsa: dict) -> None:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from aevum.verify._core import verify_receipt_tsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
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
        wrong_cert_pem = wrong_cert.public_bytes(serialization.Encoding.PEM)

        cose_bytes = _make_cose(
            mock_tsa["signature_bytes"],
            {_COSE_CTT_LABEL: mock_tsa["tsa_token_bytes"]},
        )
        assert verify_receipt_tsa(cose_bytes, tsa_root_cert=wrong_cert_pem) is False

    def test_tampered_token_bytes_returns_false(self, mock_tsa: dict) -> None:
        cose_bytes = _make_cose(
            mock_tsa["signature_bytes"],
            {_COSE_CTT_LABEL: b"not-a-real-token"},
        )
        from aevum.verify._core import verify_receipt_tsa
        assert verify_receipt_tsa(cose_bytes, tsa_root_cert=mock_tsa["tsa_cert_pem"]) is False

    def test_malformed_cose_bytes_returns_false(self, mock_tsa: dict) -> None:
        from aevum.verify._core import verify_receipt_tsa
        assert verify_receipt_tsa(b"\xff\xff not cbor", tsa_root_cert=mock_tsa["tsa_cert_pem"]) is False

    def test_non_4_element_array_returns_false(self, mock_tsa: dict) -> None:
        from aevum.verify._core import verify_receipt_tsa
        bad = cbor2.dumps({"not": "cose"})
        assert verify_receipt_tsa(bad, tsa_root_cert=mock_tsa["tsa_cert_pem"]) is False


class TestReceiptTsaIndependence:
    def test_module_never_imports_aevum_publish(self) -> None:
        """verify_receipt_tsa must not import aevum.publish — independent reimplementation."""
        import ast

        import aevum.verify._core as _core_mod
        tree = ast.parse(Path(_core_mod.__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("aevum.publish"), (
                        f"import {alias.name} found — independence violated"
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith("aevum.publish"), (
                    f"from {module} import ... found — independence violated"
                )
