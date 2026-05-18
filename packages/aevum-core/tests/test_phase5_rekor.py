# SPDX-License-Identifier: Apache-2.0
import base64
import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from aevum.core.audit.rekor_anchor import REKOR_TIMEOUT, REKOR_URL, RekorAnchor
from aevum.core.exceptions import RekorVerificationError


def _make_rekor_response(chain_hash: str, uuid: str = "abc123uuid") -> dict:
    """Build a minimal but structurally-valid Rekor hashedrekord response."""
    body = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {"data": {"hash": {"algorithm": "sha256", "value": chain_hash}}},
    }
    body_b64 = base64.b64encode(json.dumps(body).encode()).decode()
    return {uuid: {"body": body_b64, "logIndex": 42}}


class TestRekorAnchorUnit:
    def test_disabled_returns_none(self) -> None:
        anchor = RekorAnchor(enabled=False)
        result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_network_error_returns_none(self) -> None:
        with patch(
            "aevum.core.audit.rekor_anchor.httpx.post",
            side_effect=httpx.RequestError("timeout"),
        ):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_http_error_returns_none(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_exception_in_post_returns_none(self) -> None:
        with patch(
            "aevum.core.audit.rekor_anchor.httpx.post",
            side_effect=Exception("unexpected"),
        ):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_200_response_returns_dict(self) -> None:
        chain_hash = "a" * 64
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_rekor_response(chain_hash)
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root(chain_hash, b"\x00" * 64, b"\x00" * 32)
        assert isinstance(result, dict)
        assert "abc123uuid" in result

    def test_201_response_returns_dict(self) -> None:
        chain_hash = "b" * 64
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = _make_rekor_response(chain_hash, uuid="def456uuid")
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root(chain_hash, b"\x00" * 64, b"\x00" * 32)
        assert isinstance(result, dict)
        assert "def456uuid" in result

    def test_hash_mismatch_returns_none(self) -> None:
        """Mitigation for CVE-2026-22703: mismatched hash triggers circuit breaker."""
        chain_hash = "a" * 64
        wrong_hash = "b" * 64
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_rekor_response(wrong_hash)
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root(chain_hash, b"\x00" * 64, b"\x00" * 32)
        assert result is None  # circuit breaker caught RekorVerificationError

    def test_verify_rekor_entry_raises_on_mismatch(self) -> None:
        """_verify_rekor_entry raises directly on hash mismatch (CVE-2026-22703)."""
        from aevum.core.audit.rekor_anchor import _verify_rekor_entry
        valid_entry = _make_rekor_response("a" * 64)
        with pytest.raises(RekorVerificationError, match="mismatch"):
            _verify_rekor_entry(valid_entry, "b" * 64)

    def test_404_response_returns_none(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_connection_error_returns_none(self) -> None:
        with patch(
            "aevum.core.audit.rekor_anchor.httpx.post",
            side_effect=httpx.ConnectError("refused"),
        ):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_custom_url_used(self) -> None:
        anchor = RekorAnchor(rekor_url="https://example.com/api/entries", enabled=False)
        assert anchor._url == "https://example.com/api/entries"

    def test_default_url_is_sigstore(self) -> None:
        anchor = RekorAnchor()
        assert anchor._url == REKOR_URL
        assert "rekor.sigstore.dev" in anchor._url

    def test_aevum_rekor_url_env_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AEVUM_REKOR_URL env var must override the module-level default."""
        import importlib

        import aevum.core.audit.rekor_anchor as mod

        monkeypatch.setenv("AEVUM_REKOR_URL", "https://private.rekor.example/api/v2/log/entries")
        importlib.reload(mod)
        try:
            assert mod.REKOR_URL == "https://private.rekor.example/api/v2/log/entries"
        finally:
            importlib.reload(mod)  # restore original state

    def test_default_timeout(self) -> None:
        anchor = RekorAnchor()
        assert anchor._timeout == REKOR_TIMEOUT

    def test_custom_timeout(self) -> None:
        anchor = RekorAnchor(timeout=30.0)
        assert anchor._timeout == 30.0

    def test_runtime_error_returns_none(self) -> None:
        with patch(
            "aevum.core.audit.rekor_anchor.httpx.post",
            side_effect=RuntimeError("unexpected runtime error"),
        ):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result is None

    def test_base64_encoding_in_request(self) -> None:
        chain_hash = "a" * 64
        captured: list[dict] = []

        def mock_post(url: str, **kwargs: object) -> MagicMock:
            captured.append(kwargs)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _make_rekor_response(chain_hash)
            return mock_resp

        with patch("aevum.core.audit.rekor_anchor.httpx.post", side_effect=mock_post):
            anchor = RekorAnchor()
            sig = b"A" * 64
            pub = b"B" * 32
            anchor.anchor_chain_root(chain_hash, sig, pub)

        payload = captured[0]["json"]
        assert payload["spec"]["signature"]["content"] == base64.b64encode(sig).decode("ascii")
        assert payload["spec"]["signature"]["publicKey"]["content"] == base64.b64encode(pub).decode("ascii")


@pytest.mark.integration
class TestRekorAnchorLive:
    def test_live_rekor_anchor(self) -> None:
        """Live call to Rekor. Requires network. Run with: pytest -m integration"""
        import os

        anchor = RekorAnchor()
        h = "a" * 64
        sig = os.urandom(64)
        pub = os.urandom(32)
        result = anchor.anchor_chain_root(h, sig, pub)
        assert result is None or isinstance(result, dict)
