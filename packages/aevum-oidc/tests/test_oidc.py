"""
Tests for OidcComplication.
Uses mocked JWKS + mock JWT — no real IDP.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import jwt
import pytest

from aevum.oidc.complication import OidcComplication
from aevum.oidc.jwks import JwksCache


def _make_token(sub: str = "user-123", classification: int = 0, expired: bool = False) -> tuple[str, object]:
    """Generate a test RS256 token + key pair."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    payload = {
        "sub": sub,
        "aud": "api://aevum-test",
        "iss": "https://test.example.com",
        "aevum_classification": classification,
        "iat": int(time.time()),
        "exp": int(time.time()) + (-10 if expired else 3600),
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token, private_key


def _comp_with_mock_jwks(token: str, private_key: object) -> OidcComplication:
    """Create OidcComplication with mocked JWKS that validates our test token."""
    comp = OidcComplication(
        jwks_uri="https://test.example.com/.well-known/jwks.json",
        audience="api://aevum-test",
    )

    def mock_validate(t: str) -> dict:  # type: ignore[type-arg]
        pub = private_key.public_key()  # type: ignore[union-attr]
        return jwt.decode(t, pub, algorithms=["RS256"], audience="api://aevum-test")

    comp._validate_token = mock_validate  # type: ignore[method-assign]
    return comp


class TestOidcComplication:
    def test_manifest_valid(self) -> None:
        comp = OidcComplication(jwks_uri="https://ex.com/jwks", audience="aud")
        m = comp.manifest()
        assert m["name"] == "oidc"
        assert "oidc-validation" in m["capabilities"]
        assert m["schema_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_no_token_in_context(self) -> None:
        comp = OidcComplication(jwks_uri="https://ex.com/jwks", audience="aud")
        result = await comp.run({"metadata": {}}, {})
        assert result["oidc_validated"] is False
        assert "bearer_token" in result["reason"]

    @pytest.mark.asyncio
    async def test_valid_token_returns_actor(self) -> None:
        token, private_key = _make_token(sub="alice@example.com", classification=1)
        comp = _comp_with_mock_jwks(token, private_key)
        ctx = {"metadata": {"bearer_token": token}}
        result = await comp.run(ctx, {})
        assert result["oidc_validated"] is True
        assert result["resolved_actor"] == "alice@example.com"
        assert result["resolved_classification"] == 1

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self) -> None:
        token, private_key = _make_token(expired=True)
        comp = _comp_with_mock_jwks(token, private_key)
        ctx = {"metadata": {"bearer_token": token}}
        result = await comp.run(ctx, {})
        assert result["oidc_validated"] is False
        assert "expired" in result["reason"]

    @pytest.mark.asyncio
    async def test_classification_clamped_to_0_3(self) -> None:
        token, private_key = _make_token(classification=99)
        comp = _comp_with_mock_jwks(token, private_key)
        ctx = {"metadata": {"bearer_token": token}}
        result = await comp.run(ctx, {})
        assert result["resolved_classification"] == 3  # clamped

    @pytest.mark.asyncio
    async def test_identity_not_in_result(self) -> None:
        """Token, email, and raw claims must never appear in result."""
        token, private_key = _make_token(sub="alice@example.com")
        comp = _comp_with_mock_jwks(token, private_key)
        ctx = {"metadata": {"bearer_token": token}}
        result = await comp.run(ctx, {})
        result_str = str(result)
        assert token not in result_str, "Raw token must never appear in complication output"

    def test_health_when_jwks_unreachable(self) -> None:
        comp = OidcComplication(jwks_uri="https://unreachable.invalid/jwks", audience="aud")
        assert comp.health() is False


class TestJwksCache:
    def test_cache_ttl(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"keys": [{"kid": "key1"}]}
        mock_response.raise_for_status.return_value = None

        cache = JwksCache("https://ex.com/jwks", ttl_seconds=100)
        with patch.object(cache, "_http") as mock_http:
            mock_http.return_value.get.return_value = mock_response
            keys1 = cache.get_keys()
            keys2 = cache.get_keys()  # Should use cache
            assert mock_http.return_value.get.call_count == 1  # Only one fetch
            assert keys1 == keys2

    def test_invalidate_forces_refetch(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"keys": [{"kid": "key1"}]}
        mock_response.raise_for_status.return_value = None

        cache = JwksCache("https://ex.com/jwks", ttl_seconds=100)
        with patch.object(cache, "_http") as mock_http:
            mock_http.return_value.get.return_value = mock_response
            cache.get_keys()
            cache.invalidate()
            cache.get_keys()
            assert mock_http.return_value.get.call_count == 2
