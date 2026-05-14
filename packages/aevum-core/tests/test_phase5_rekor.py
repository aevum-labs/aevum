# SPDX-License-Identifier: Apache-2.0
from unittest.mock import MagicMock, patch

import httpx
import pytest

from aevum.core.audit.rekor_anchor import REKOR_TIMEOUT, REKOR_URL, RekorAnchor


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
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"uuid": "abc123", "logIndex": 42}
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result == {"uuid": "abc123", "logIndex": 42}

    def test_201_response_returns_dict(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"uuid": "def456"}
        with patch("aevum.core.audit.rekor_anchor.httpx.post", return_value=mock_resp):
            anchor = RekorAnchor()
            result = anchor.anchor_chain_root("a" * 64, b"\x00" * 64, b"\x00" * 32)
        assert result == {"uuid": "def456"}

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
        import base64

        captured: list[dict] = []

        def mock_post(url: str, **kwargs: object) -> MagicMock:
            captured.append(kwargs)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {}
            return mock_resp

        with patch("aevum.core.audit.rekor_anchor.httpx.post", side_effect=mock_post):
            anchor = RekorAnchor()
            sig = b"A" * 64
            pub = b"B" * 32
            anchor.anchor_chain_root("a" * 64, sig, pub)

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
