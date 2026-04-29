"""
Tests for OPA sidecar integration in PolicyBridge.
Uses mocked httpx -- no real OPA sidecar required in CI.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from aevum.core.policy.bridge import PolicyBridge


class TestOPASidecar:
    def test_no_opa_url_returns_true(self) -> None:
        """Infrastructure policy is permissive when no OPA is configured."""
        bridge = PolicyBridge()
        assert bridge.evaluate_infrastructure(
            actor="actor", operation="query", resource={}
        ) is True

    def test_opa_permit(self) -> None:
        """OPA returning true permits the request."""
        bridge = PolicyBridge(opa_url="http://opa:8181")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"result": True}
        mock_resp.raise_for_status.return_value = None
        with patch.object(bridge._http_client(), "post", return_value=mock_resp):
            assert bridge.evaluate_infrastructure(
                actor="actor", operation="query", resource={}
            ) is True

    def test_opa_deny(self) -> None:
        """OPA returning false denies the request."""
        bridge = PolicyBridge(opa_url="http://opa:8181")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"result": False}
        mock_resp.raise_for_status.return_value = None
        with patch.object(bridge._http_client(), "post", return_value=mock_resp):
            assert bridge.evaluate_infrastructure(
                actor="actor", operation="query", resource={}
            ) is False

    def test_opa_timeout_fail_closed(self) -> None:
        """Network timeout fails closed -- denies the request."""
        bridge = PolicyBridge(opa_url="http://opa:8181")
        with patch.object(
            bridge._http_client(), "post",
            side_effect=httpx.TimeoutException("timeout")
        ):
            assert bridge.evaluate_infrastructure(
                actor="actor", operation="query", resource={}
            ) is False

    def test_opa_error_fail_closed(self) -> None:
        """Any OPA sidecar error fails closed -- denies the request."""
        bridge = PolicyBridge(opa_url="http://opa:8181")
        with patch.object(
            bridge._http_client(), "post",
            side_effect=Exception("connection refused")
        ):
            assert bridge.evaluate_infrastructure(
                actor="actor", operation="query", resource={}
            ) is False

    def test_opa_url_trailing_slash_stripped(self) -> None:
        """Trailing slash in OPA URL is normalised to prevent double-slash paths."""
        bridge = PolicyBridge(opa_url="http://opa:8181/")
        assert bridge._opa_url == "http://opa:8181"

    def test_opa_missing_result_key_fail_closed(self) -> None:
        """Unexpected OPA response format fails closed."""
        bridge = PolicyBridge(opa_url="http://opa:8181")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}  # No "result" key
        mock_resp.raise_for_status.return_value = None
        with patch.object(bridge._http_client(), "post", return_value=mock_resp):
            assert bridge.evaluate_infrastructure(
                actor="actor", operation="query", resource={}
            ) is False
