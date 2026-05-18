# SPDX-License-Identifier: Apache-2.0
"""
Tests for Track A:
- Startup consent grant (generate endpoint no longer 500s)
- POST /v1/ingest/scan-results OIDC verification
"""
from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

# ---------------------------------------------------------------------------
# Test fixtures: RSA key pair and JWT helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_private_key() -> Any:
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


@pytest.fixture(scope="module")
def test_jwks(rsa_private_key: Any) -> dict[str, Any]:
    public_key = rsa_private_key.public_key()
    alg = RSAAlgorithm(RSAAlgorithm.SHA256)
    jwk_dict: dict[str, Any] = json.loads(alg.to_jwk(public_key))
    jwk_dict["kid"] = "test-key-id"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return {"keys": [jwk_dict]}


def _make_token(
    private_key: Any,
    *,
    repository: str = "aevum-labs/aevum",
    audience: str = "aevum-maintainer",
    kid: str = "test-key-id",
    exp_offset: int = 3600,
) -> str:
    return jwt.encode(
        {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            "repository": repository,
            "sub": f"repo:{repository}:ref:refs/heads/main",
            "exp": int(time.time()) + exp_offset,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# A1 — Startup consent grant: generate endpoint returns 200, not 500
# ---------------------------------------------------------------------------


def test_generate_endpoint_returns_200_not_500(client: Any) -> None:
    """Startup consent grant means generate no longer 500s on first call."""
    resp = client.post("/v1/compliance-pack/generate", json={"version": "0.4.0"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# A2 — POST /v1/ingest/scan-results: auth header validation
# ---------------------------------------------------------------------------


def test_ingest_scan_results_missing_auth_header(client: Any) -> None:
    resp = client.post("/v1/ingest/scan-results", json={"vulnerabilities": []})
    assert resp.status_code == 401
    assert "Authorization" in resp.json()["detail"] or "Missing" in resp.json()["detail"]


def test_ingest_scan_results_malformed_auth_header(client: Any) -> None:
    resp = client.post(
        "/v1/ingest/scan-results",
        json={"vulnerabilities": []},
        headers={"Authorization": "Basic abc123"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# A2 — OIDC token verification (mocking _fetch_jwks)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_github_oidc_token_valid(
    rsa_private_key: Any, test_jwks: dict[str, Any]
) -> None:
    from aevum_maintainer.server import verify_github_oidc_token

    token = _make_token(rsa_private_key)
    with patch("aevum_maintainer.server._fetch_jwks", new=AsyncMock(return_value=test_jwks)):
        claims = await verify_github_oidc_token(token)
    assert claims["repository"] == "aevum-labs/aevum"


@pytest.mark.asyncio
async def test_verify_github_oidc_token_wrong_repo(
    rsa_private_key: Any, test_jwks: dict[str, Any]
) -> None:
    from aevum_maintainer.server import verify_github_oidc_token
    from fastapi import HTTPException

    token = _make_token(rsa_private_key, repository="evil-org/evil-repo")
    with (
        patch("aevum_maintainer.server._fetch_jwks", new=AsyncMock(return_value=test_jwks)),
        pytest.raises(HTTPException) as exc_info,
    ):
        await verify_github_oidc_token(token)
    assert exc_info.value.status_code == 403
    assert "evil-org/evil-repo" in exc_info.value.detail


@pytest.mark.asyncio
async def test_verify_github_oidc_token_invalid_jwt() -> None:
    from aevum_maintainer.server import verify_github_oidc_token
    from fastapi import HTTPException

    with (
        patch("aevum_maintainer.server._fetch_jwks", new=AsyncMock(return_value={"keys": []})),
        pytest.raises(HTTPException) as exc_info,
    ):
        await verify_github_oidc_token("not.a.valid.jwt")
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_github_oidc_token_no_matching_key(
    rsa_private_key: Any,
) -> None:
    from aevum_maintainer.server import verify_github_oidc_token
    from fastapi import HTTPException

    token = _make_token(rsa_private_key, kid="different-kid")
    # JWKS has key with "test-key-id", token has "different-kid"
    alg = RSAAlgorithm(RSAAlgorithm.SHA256)
    jwk_dict: dict[str, Any] = json.loads(alg.to_jwk(rsa_private_key.public_key()))
    jwk_dict["kid"] = "test-key-id"
    mismatched_jwks = {"keys": [jwk_dict]}

    with (
        patch("aevum_maintainer.server._fetch_jwks", new=AsyncMock(return_value=mismatched_jwks)),
        pytest.raises(HTTPException) as exc_info,
    ):
        await verify_github_oidc_token(token)
    assert exc_info.value.status_code == 401
    assert "No matching key" in exc_info.value.detail


# ---------------------------------------------------------------------------
# A2 — Full endpoint test with mocked OIDC verifier
# ---------------------------------------------------------------------------


def test_ingest_scan_results_valid_token(
    client: Any, rsa_private_key: Any, test_jwks: dict[str, Any]
) -> None:
    """End-to-end: valid OIDC token → 200 with audit_id."""
    mock_claims = {
        "repository": "aevum-labs/aevum",
        "sub": "repo:aevum-labs/aevum:ref:refs/heads/main",
        "iss": "https://token.actions.githubusercontent.com",
    }
    with patch(
        "aevum_maintainer.server.verify_github_oidc_token",
        new=AsyncMock(return_value=mock_claims),
    ):
        resp = client.post(
            "/v1/ingest/scan-results",
            json={"vulnerabilities": [], "packages": 42},
            headers={"Authorization": "Bearer fake-but-mocked-token"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "audit_id" in body
    assert body["status"] == "ok"


def test_ingest_scan_results_oidc_rejection_propagates(client: Any) -> None:
    """OIDC 403 from wrong repo bubbles up to the caller."""
    from fastapi import HTTPException

    async def _reject(_token: str) -> dict[str, Any]:
        raise HTTPException(status_code=403, detail="Token from unexpected repo: 'evil/repo'")

    with patch("aevum_maintainer.server.verify_github_oidc_token", new=_reject):
        resp = client.post(
            "/v1/ingest/scan-results",
            json={},
            headers={"Authorization": "Bearer bad-token"},
        )
    assert resp.status_code == 403
