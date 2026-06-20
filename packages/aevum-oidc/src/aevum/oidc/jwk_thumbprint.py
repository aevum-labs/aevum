# SPDX-License-Identifier: Apache-2.0
"""
RFC 7638 JWK thumbprint helpers -- pure stdlib, no JOSE/JWKS library dependency.

A recorded v2 principal_binding never carries a raw key, only `cnf.jkt`: the
RFC 7638 thumbprint of the holder's public key (DD7, docs/spec/aevum-signing-v2.md).
This module lets OidcJwtBindingVerifier (1) check that a recorded `jkt` is at
least well-formed -- the right shape to BE a SHA-256 RFC 7638 thumbprint -- and
(2), if the caller separately supplies the holder's JWK, recompute its
thumbprint and compare. Neither operation needs a JWKS-fetching library or
network access (DD-I3); that is reserved for the optional jwks_fetch module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

# RFC 7638 thumbprint = base64url(SHA-256(canonical JWK)), no padding.
# SHA-256 is a 32-byte digest; base64url-no-pad of 32 bytes is always 43
# characters from the URL-safe alphabet. A jkt of any other shape cannot be a
# well-formed RFC 7638 SHA-256 thumbprint, regardless of what it claims to be.
_THUMBPRINT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

# RFC 7638 §3.2/3.3: the required members to canonicalize per key type, in the
# exact member-name set the RFC mandates (order does not matter -- json.dumps
# below sorts keys before hashing).
_REQUIRED_MEMBERS: dict[str, tuple[str, ...]] = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "oct": ("k", "kty"),
    "OKP": ("crv", "kty", "x"),
}


def is_well_formed_thumbprint(jkt: Any) -> bool:
    """True if `jkt` has the shape of an RFC 7638 SHA-256 thumbprint.

    This is a structural check only -- it does not confirm the thumbprint
    corresponds to any actual key. See compute_jwk_thumbprint for that.
    """
    return isinstance(jkt, str) and _THUMBPRINT_RE.fullmatch(jkt) is not None


def compute_jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Compute the RFC 7638 thumbprint of `jwk`.

    Raises ValueError for an unsupported or missing `kty`, or a JWK missing one
    of its required members -- this is a caller-supplied-key validation
    function, not a fail-closed verification step; OidcJwtBindingVerifier
    catches and translates these into a failure_reasons entry.
    """
    kty = jwk.get("kty")
    members = _REQUIRED_MEMBERS.get(kty) if isinstance(kty, str) else None
    if members is None:
        raise ValueError(f"unsupported or missing kty for thumbprint: {kty!r}")
    canonical = {k: jwk[k] for k in members}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(encoded).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
