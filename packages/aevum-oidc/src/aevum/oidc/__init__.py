"""
aevum.oidc — OIDC token validation complication.

Validates Bearer tokens from enterprise IDPs (Azure AD, Okta, Ping).
NEVER stores identity — resolves actor string from sub claim at query time.
Maps aevum_classification claim to classification level (0-3).

Usage:
    from aevum.oidc import OidcComplication
    comp = OidcComplication(jwks_uri="https://login.example.com/.well-known/jwks.json",
                            audience="api://aevum")
    engine.install_complication(comp, auto_approve=True)
"""

from aevum.oidc.complication import OidcComplication

__version__ = "0.1.0"

__all__ = ["OidcComplication"]
