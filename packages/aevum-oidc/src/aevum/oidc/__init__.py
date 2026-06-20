# SPDX-License-Identifier: Apache-2.0
"""
aevum.oidc — OIDC/JWT principal-binding verifier adapter.

Implements aevum.core.protocols.principal_binding_verifier.PrincipalBindingVerifier
for the `oidc-jwt` scheme: re-verifies a recorded v2 principal_binding blob
(docs/spec/aevum-signing-v2.md) for well-formedness, validity window, issuer,
and audience. See OidcJwtBindingVerifier's docstring for the full HONESTY SCOPE
-- this adapter does not re-verify the issuer's signature or a bearer token.

Usage:
    from aevum.oidc import OidcJwtBindingVerifier

    verifier = OidcJwtBindingVerifier()
    result = verifier.verify(
        {"principal_binding": event.principal_binding},
        at_time=datetime.now(UTC),
        expected_issuers=["https://idp.example"],
        expected_audience="aevum",
    )
    result.verified            # bool
    result.checks_performed    # e.g. ["structure", "validity_window", ...]
    result.checks_not_performed  # always names issuer-signature + token-replay
"""

from aevum.oidc.verifier import OidcJwtBindingVerifier

__version__ = "0.8.0"
__all__ = ["OidcJwtBindingVerifier"]
