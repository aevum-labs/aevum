# SPDX-License-Identifier: Apache-2.0
"""
Optional live JWKS fetch convenience (DD-I3 / DD-I2).

verify() (verifier.py) never needs network access -- it operates entirely on
caller-supplied trust material. This module is the one place a network fetch
happens, and it is import-isolated: importing aevum.oidc does not pull in
PyJWT, only calling a function in this module does. PyJWT itself is declared
as the `jwks` optional extra in pyproject.toml, never a hard dependency, so
the offline verify path has zero JWKS-library footprint.

This is a convenience for resolving a holder key to pass into
OidcJwtBindingVerifier.verify(holder_jwk=...); it does not change what
verify() checks or claims to check.
"""

from __future__ import annotations

from typing import Any


def live_jwks_fetch(jwks_url: str, kid: str) -> dict[str, Any]:
    """Fetch the JWKS at `jwks_url` and return the JWK whose `kid` matches.

    Requires PyJWT: pip install aevum-oidc[jwks]. Raises ImportError up front
    (with the install hint) if it is not installed, and propagates PyJWT's own
    errors for network failures or an unknown `kid` -- this is a live network
    call, not part of the fail-closed offline verify() path.
    """
    try:
        from jwt import PyJWKClient
    except ImportError as exc:
        raise ImportError(
            "live_jwks_fetch requires PyJWT. Install with: pip install aevum-oidc[jwks]"
        ) from exc

    client = PyJWKClient(jwks_url)
    signing_key = client.get_signing_key(kid)
    jwk_dict: dict[str, Any] = signing_key.Algorithm.to_jwk(signing_key.key, as_dict=True)
    return jwk_dict


def verify_with_live_jwks(
    verifier: Any,
    binding: dict[str, Any],
    *,
    at_time: Any,
    jwks_url: str,
    kid: str,
    expected_issuers: list[str] | None = None,
    expected_audience: str | None = None,
) -> Any:
    """Resolve `kid` from `jwks_url`, then delegate to the same sync
    `verifier.verify()` used by the offline path -- the network fetch is
    isolated to resolving WHICH key to pass; the verification logic itself is
    not duplicated."""
    holder_jwk = live_jwks_fetch(jwks_url, kid)
    return verifier.verify(
        binding,
        at_time=at_time,
        expected_issuers=expected_issuers,
        expected_audience=expected_audience,
        holder_jwk=holder_jwk,
    )
