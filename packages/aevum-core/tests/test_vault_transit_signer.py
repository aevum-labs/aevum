# SPDX-License-Identifier: Apache-2.0
"""
Tests for VaultTransitSigner.

All tests mock the HTTP calls — no live Vault instance required.
Integration tests (marked @pytest.mark.integration) require a live Vault instance:
  VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root AEVUM_VAULT_TEST_KEY=aevum-signing-test
See docs/deployment/vault-setup.md for setup instructions.
"""

from __future__ import annotations

import base64
import os
from unittest.mock import MagicMock, patch

import pytest

from aevum.core.audit.signer import VaultTransitSigner

_VAULT_SKIP = pytest.mark.skipif(
    not os.environ.get("VAULT_ADDR"),
    reason="VAULT_ADDR not set — Vault integration test requires live Vault",
)


def _make_fake_sig_b64url(raw_bytes: bytes = b"\xab" * 64) -> str:
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode()


def _make_vault_sign_response(sig_bytes: bytes = b"\xab" * 64) -> MagicMock:
    sig_b64 = _make_fake_sig_b64url(sig_bytes)
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "data": {"signature": f"vault:v1:{sig_b64}"}
    }
    return resp


def _make_vault_key_response(pub_b64: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "data": {
            "latest_version": 1,
            "keys": {
                "1": {"public_key": pub_b64}
            }
        }
    }
    return resp


class TestVaultTransitSignerInit:
    def test_key_id_includes_vault_addr_and_key_name(self):
        signer = VaultTransitSigner("aevum-signing", vault_addr="http://vault:8200", token="tok")
        assert "vault:8200" in signer.key_id
        assert "aevum-signing" in signer.key_id

    def test_provenance_is_vault_transit(self):
        signer = VaultTransitSigner("aevum-signing", token="tok")
        assert signer.provenance == "vault-transit"

    def test_key_scheme_is_ed25519_plus_vault_transit(self):
        signer = VaultTransitSigner("aevum-signing", token="tok")
        assert signer.key_scheme == "ed25519+vault-transit"

    def test_reads_vault_addr_from_env(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "http://custom-vault:9200")
        signer = VaultTransitSigner("my-key", token="tok")
        assert "custom-vault:9200" in signer.key_id

    def test_reads_token_from_env(self, monkeypatch):
        monkeypatch.setenv("VAULT_TOKEN", "env-token")
        signer = VaultTransitSigner("my-key", vault_addr="http://vault:8200")
        assert signer._token == "env-token"


class TestVaultTransitSignerSign:
    def test_sign_posts_to_correct_url(self):
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        digest = b"\xde\xad\xbe\xef" * 8  # 32 bytes

        mock_resp = _make_vault_sign_response()
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp
            signer.sign(digest)
            call_args = mock_client.post.call_args
            assert "aevum-key" in call_args[0][0]
            assert call_args[1]["json"]["prehashed"] is False

    def test_sign_sends_base64_encoded_digest(self):
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        digest = b"\x01" * 32
        expected_b64 = base64.b64encode(digest).decode()

        mock_resp = _make_vault_sign_response()
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp
            signer.sign(digest)
            body = mock_client.post.call_args[1]["json"]
            assert body["input"] == expected_b64

    def test_sign_returns_raw_bytes(self):
        raw = b"\xab" * 64
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        mock_resp = _make_vault_sign_response(raw)
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp
            result = signer.sign(b"\x00" * 32)
        assert result == raw

    def test_sign_raises_on_http_error(self):
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        bad_resp = MagicMock()
        bad_resp.status_code = 403
        bad_resp.text = "permission denied"
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = bad_resp
            with pytest.raises(RuntimeError, match="403"):
                signer.sign(b"\x00" * 32)


class TestVaultTransitSignerPublicKey:
    def test_public_key_bytes_fetches_from_vault(self):
        raw_key = b"\x42" * 32
        pub_b64 = base64.b64encode(raw_key).decode()
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        mock_resp = _make_vault_key_response(pub_b64)
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            result = signer.public_key_bytes()
        assert result == raw_key

    def test_public_key_bytes_is_cached(self):
        raw_key = b"\x42" * 32
        pub_b64 = base64.b64encode(raw_key).decode()
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        mock_resp = _make_vault_key_response(pub_b64)
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = mock_resp
            signer.public_key_bytes()
            signer.public_key_bytes()
            # Second call should not make another HTTP request
            assert mock_client.get.call_count == 1

    def test_public_key_raises_on_http_error(self):
        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")
        bad_resp = MagicMock()
        bad_resp.status_code = 404
        bad_resp.text = "key not found"
        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.get.return_value = bad_resp
            with pytest.raises(RuntimeError, match="404"):
                signer.public_key_bytes()


class TestVaultTransitSignerWithSigchain:
    def test_sigchain_uses_vault_signer(self, monkeypatch):
        """VaultTransitSigner integrates with Sigchain (mocked HTTP)."""
        from aevum.core.audit.sigchain import Sigchain

        raw_sig = b"\xcd" * 64
        raw_key = b"\x42" * 32
        pub_b64 = base64.b64encode(raw_key).decode()

        sign_resp = _make_vault_sign_response(raw_sig)
        key_resp = _make_vault_key_response(pub_b64)

        signer = VaultTransitSigner("aevum-key", vault_addr="http://vault:8200", token="root")

        with patch("httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__enter__.return_value
            mock_client.post.return_value = sign_resp
            mock_client.get.return_value = key_resp

            sigchain = Sigchain(signer=signer)
            event = sigchain.new_event(
                event_type="test.event",
                payload={"k": "v"},
                actor="test",
            )

        assert event.signer_key_id == signer.key_id
        assert event.signature != ""


def _live_signer() -> VaultTransitSigner:
    return VaultTransitSigner(
        key_name=os.environ.get("AEVUM_VAULT_TEST_KEY", "aevum-signing-test"),
        vault_addr=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        token=os.environ.get("VAULT_TOKEN", ""),
    )


@pytest.mark.integration
@_VAULT_SKIP
class TestVaultTransitSignerLive:
    """Live integration tests — require VAULT_ADDR, VAULT_TOKEN, AEVUM_VAULT_TEST_KEY."""

    def test_sign_returns_bytes(self):
        signer = _live_signer()
        sig = signer.sign(b"aevum vault live test 2026")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_verify_valid_signature(self):
        signer = _live_signer()
        payload = b"aevum vault live test 2026"
        sig = signer.sign(payload)
        assert signer.verify(payload, sig) is True

    def test_verify_rejects_tampered_payload(self):
        signer = _live_signer()
        payload = b"aevum vault live test 2026"
        sig = signer.sign(payload)
        assert signer.verify(b"tampered payload", sig) is False

    def test_verify_rejects_corrupted_signature(self):
        signer = _live_signer()
        payload = b"aevum vault live test 2026"
        sig = signer.sign(payload)
        corrupted = bytes([b ^ 0xFF for b in sig[:32]]) + sig[32:]
        assert signer.verify(payload, corrupted) is False

    def test_key_id_is_not_empty(self):
        signer = _live_signer()
        assert signer.key_id != ""
        assert len(signer.key_id) > 0

    def test_does_not_use_production_key(self):
        signer = _live_signer()
        assert signer._key_name != "aevum-signing", (
            "Integration tests must use the test key, not the production key"
        )

    def test_receipt_encoder_accepts_vault_signer(self):
        from aevum.publish.encoder import ReceiptEncoder
        signer = _live_signer()
        encoder = ReceiptEncoder(signer=signer)
        assert encoder is not None

    def test_circuit_breaker_on_vault_unavailable(self):
        import httpx
        signer = VaultTransitSigner(
            key_name="aevum-signing-test",
            vault_addr="http://127.0.0.1:19999",
            token="dev-root",
            timeout=1.0,
        )
        with pytest.raises(httpx.TransportError):
            signer.sign(b"aevum vault live test 2026")
