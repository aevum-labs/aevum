"""
OidcComplication — validates OIDC Bearer tokens.

NEVER stores identity. Resolves actor from sub claim at query time.
Maps aevum_classification claim → classification level (0-3).
"""

from __future__ import annotations

import logging
from typing import Any

import jwt  # PyJWT

from aevum.oidc.jwks import JwksCache

logger = logging.getLogger(__name__)

_CLASSIFICATION_CLAIMS = ("aevum_classification", "aevum:classification")


class OidcComplication:
    """
    OIDC token validation complication.

    Args:
        jwks_uri: JWKS endpoint of your IDP
        audience: Expected token audience (aud claim)
        algorithms: Signing algorithms to accept (default RS256)
        classification_claim: JWT claim name for classification level

    Identity is resolved from the token sub claim.
    Classification is resolved from the aevum_classification claim (default 0).
    Identity and tokens are NEVER stored in the knowledge graph.
    """

    name = "oidc"
    version = "0.1.0"
    capabilities = ["oidc-validation", "actor-resolution"]

    def __init__(
        self,
        jwks_uri: str,
        audience: str,
        algorithms: list[str] | None = None,
        classification_claim: str = "aevum_classification",
    ) -> None:
        self._jwks_cache = JwksCache(jwks_uri)
        self._audience = audience
        self._algorithms = algorithms or ["RS256"]
        self._classification_claim = classification_claim

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": "OIDC token validation — resolves actor identity at query time",
            "capabilities": list(self.capabilities),
            "classification_max": 0,
            "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    def health(self) -> bool:
        """Healthy if the JWKS endpoint is reachable."""
        try:
            self._jwks_cache.get_keys()
            return True
        except Exception:
            return False

    async def run(self, ctx: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        """
        Validate a Bearer token from the request context.

        Expects ctx["metadata"]["bearer_token"] to be set by the caller.
        Returns resolved actor and classification, or an error dict.
        NEVER returns or stores the raw token.
        """
        token = ctx.get("metadata", {}).get("bearer_token")
        if not token:
            return {"oidc_validated": False, "reason": "no bearer_token in context"}

        try:
            claims = self._validate_token(token)
        except jwt.ExpiredSignatureError:
            return {"oidc_validated": False, "reason": "token expired"}
        except jwt.InvalidTokenError as e:
            return {"oidc_validated": False, "reason": f"invalid token: {e}"}

        # Resolve actor from sub claim — never store the token itself
        actor = claims.get("sub", "")
        if not actor:
            return {"oidc_validated": False, "reason": "missing sub claim"}

        # Classification from custom claim (default 0 = public)
        raw_class = claims.get(self._classification_claim, 0)
        try:
            classification = max(0, min(3, int(raw_class)))
        except (TypeError, ValueError):
            classification = 0

        return {
            "oidc_validated": True,
            "resolved_actor": actor,
            "resolved_classification": classification,
            # Do NOT include: token, raw claims, email, name, etc.
        }

    def _validate_token(self, token: str) -> dict[str, Any]:
        """Validate JWT signature and claims against JWKS."""
        keys = self._jwks_cache.get_keys()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        # Find the matching key
        matching_keys = [k for k in keys if not kid or k.get("kid") == kid]
        if not matching_keys:
            raise jwt.InvalidTokenError(f"No matching key for kid={kid!r}")

        last_error: Exception = jwt.InvalidTokenError("No keys available")
        for key_data in matching_keys:
            try:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
                claims: dict[str, Any] = jwt.decode(
                    token,
                    public_key,  # type: ignore[arg-type]
                    algorithms=self._algorithms,
                    audience=self._audience,
                )
                return claims
            except jwt.InvalidTokenError as e:
                last_error = e
        raise last_error
