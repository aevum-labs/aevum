# SPDX-License-Identifier: Apache-2.0
"""
SpiffeBindingVerifier -- re-verifies a recorded v2 principal_binding blob
(docs/spec/aevum-signing-v2.md) built from SPIFFE JWT-SVID claims.

HONESTY SCOPE -- read before trusting a `verified=True` result. This adapter
checks that a RECORDED binding is well-formed, within its validity window,
from an expected trust domain, and for the expected audience. The SVID's
signature was checked once, at capture time, by whatever committed the event
(the witness model) -- it is not recorded (DD7 strips it by construction), so
this adapter cannot and does not re-verify it. It also never re-verifies a
bearer token (none is ever stored) and does not, by itself, prove the named
workload acted -- that needs a separate commitment-match against the
deployment's commitment key (see aevum.core.audit.commitment_key_store.
verify_commitment). JWT-SVID has no proof-of-possession key, so
cnf_jkt_holder_match is unconditionally a checks_not_performed entry, unlike
the OIDC adapter where it is conditionally performed when a `cnf` claim is
present. Every BindingVerificationResult names exactly what ran in
`checks_performed` and what did not in `checks_not_performed`, so the scope is
structural, not just documented here.

verify() never raises on malformed, missing, or hostile input: every failure
path returns `verified=False` with reasons (fail-closed), mirroring the
discipline aevum-verify applies to untrusted chain data.

This module has zero dependency on aevum-oidc (or vice versa) -- both are
independent siblings implementing the same neutral
aevum.core.protocols.principal_binding_verifier.PrincipalBindingVerifier
Protocol without depending on each other or on aevum-core knowing either
exists.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from aevum.core.protocols.principal_binding_verifier import BindingVerificationResult

# DD7 (core): only iss/aud/jti/iat/exp/cnf ever survive into a recorded
# principal_binding blob. JWT-SVID (https://github.com/spiffe/spiffe/blob/main/
# standards/JWT-SVID.md) does not mandate `iat` -- unlike OIDC, only iss/aud/exp
# are required here for a binding to be considered well-formed.
_REQUIRED_CLAIMS = frozenset({"iss", "aud", "exp"})

_CNF_NOT_PERFORMED = "cnf_jkt_holder_match (no PoP key in JWT-SVID)"
_ISSUER_SIGNATURE_NOT_RECORDED = "issuer_signature (not recorded)"
_TOKEN_REPLAY_NOT_STORED = "token_replay (no token stored)"


class SpiffeBindingVerifier:
    """Re-verifies recorded SPIFFE/JWT-SVID principal_binding blobs.

    `scheme` is "spiffe" -- distinct from aevum-oidc's "oidc-jwt", so a caller
    holding both adapters can dispatch on either via handles() without
    ambiguity (see TestNeutrality in the test suite).
    """

    scheme = "spiffe"

    def handles(self, binding: dict[str, Any]) -> bool:
        """True when `binding` decodes to claims with a `spiffe://` `iss` --
        declining cleanly on anything that is not SPIFFE-shaped, including
        malformed input and OIDC's `https://` issuers, is what keeps the
        neutral Protocol from silently assuming one issuer shape."""
        claims = self._decode_claims(binding)
        if claims is None:
            return False
        iss = claims.get("iss")
        return isinstance(iss, str) and iss.startswith("spiffe://")

    def verify(
        self,
        binding: dict[str, Any],
        *,
        at_time: datetime,
        expected_issuers: list[str] | None = None,
        expected_audience: str | None = None,
    ) -> BindingVerificationResult:
        checks_performed: list[str] = []
        checks_not_performed: list[str] = [
            _CNF_NOT_PERFORMED,
            _ISSUER_SIGNATURE_NOT_RECORDED,
            _TOKEN_REPLAY_NOT_STORED,
        ]
        failure_reasons: list[str] = []

        checks_performed.append("structure")
        claims = self._decode_claims(binding)
        if claims is None:
            failure_reasons.append(
                "principal_binding missing, not a string, or not valid base64url(RFC8785-JSON)"
            )
            return BindingVerificationResult(
                verified=False,
                scheme=self.scheme,
                checks_performed=checks_performed,
                checks_not_performed=checks_not_performed,
                failure_reasons=failure_reasons,
            )

        missing = sorted(_REQUIRED_CLAIMS - claims.keys())
        if missing:
            failure_reasons.append(f"missing required claim(s): {missing}")

        checks_performed.append("validity_window")
        self._check_validity_window(claims, at_time, failure_reasons)

        if expected_issuers is not None:
            checks_performed.append("issuer_match")
            if claims.get("iss") not in expected_issuers:
                failure_reasons.append(
                    f"issuer {claims.get('iss')!r} not in expected_issuers {expected_issuers!r}"
                )

        if expected_audience is not None:
            checks_performed.append("audience_match")
            aud = claims.get("aud")
            if not isinstance(aud, list) or expected_audience not in aud:
                failure_reasons.append(
                    f"expected_audience {expected_audience!r} not in aud {aud!r}"
                )

        return BindingVerificationResult(
            verified=not failure_reasons,
            scheme=self.scheme,
            checks_performed=checks_performed,
            checks_not_performed=checks_not_performed,
            failure_reasons=failure_reasons,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _check_validity_window(
        self, claims: dict[str, Any], at_time: datetime, failure_reasons: list[str]
    ) -> None:
        at_epoch = int(at_time.timestamp())

        exp = claims.get("exp")
        if exp is not None:
            if not isinstance(exp, int):
                failure_reasons.append("exp present but not a well-formed integer")
            elif at_epoch > exp:
                failure_reasons.append(
                    f"at_time {at_time.isoformat()} (epoch {at_epoch}) past exp={exp}"
                )

        # iat is not required by JWT-SVID (unlike OIDC) -- only checked if present.
        iat = claims.get("iat")
        if iat is not None:
            if not isinstance(iat, int):
                failure_reasons.append("iat present but not a well-formed integer")
            elif at_epoch < iat:
                failure_reasons.append(
                    f"at_time {at_time.isoformat()} (epoch {at_epoch}) before iat={iat}"
                )

    def _decode_claims(self, binding: Any) -> dict[str, Any] | None:
        if not isinstance(binding, Mapping):
            return None
        blob = binding.get("principal_binding")
        if not isinstance(blob, str) or not blob:
            return None
        try:
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.urlsafe_b64decode(padded)
            claims = json.loads(raw)
        except Exception:
            return None
        return claims if isinstance(claims, dict) else None
