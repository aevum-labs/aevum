# SPDX-License-Identifier: Apache-2.0
"""
OidcJwtBindingVerifier -- re-verifies a recorded v2 principal_binding blob
(docs/spec/aevum-signing-v2.md) built from OIDC/JWT claims.

HONESTY SCOPE -- read before trusting a `verified=True` result. This adapter
checks that a RECORDED binding is well-formed, within its validity window,
from an expected issuer, and for the expected audience. The credential's
signature was checked once, at capture time, by whatever committed the event
(the witness model) -- it is not recorded (DD7 strips it by construction), so
this adapter cannot and does not re-verify it. It also never re-verifies a
bearer token (none is ever stored) and does not, by itself, prove the named
subject acted -- that needs a separate commitment-match against the
deployment's commitment key (see aevum.core.audit.commitment_key_store.
verify_commitment). Every BindingVerificationResult names exactly what ran in
`checks_performed` and what did not in `checks_not_performed`, so the scope is
structural, not just documented here.

verify() never raises on malformed, missing, or hostile input: every failure
path returns `verified=False` with reasons (fail-closed), mirroring the
discipline aevum-verify applies to untrusted chain data.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from aevum.core.protocols.principal_binding_verifier import BindingVerificationResult

from aevum.oidc.jwk_thumbprint import compute_jwk_thumbprint, is_well_formed_thumbprint

# DD7 (core): only these keys ever survive into a recorded principal_binding blob.
# A binding missing iss/aud/iat/exp cannot be meaningfully checked against an
# issuer, audience, or validity window, so all four are required here for a
# binding to be considered well-formed; jti is allow-listed at commit time but
# not required for this verifier's checks (replay detection is out of scope --
# see checks_not_performed).
_REQUIRED_CLAIMS = frozenset({"iss", "aud", "iat", "exp"})

_ISSUER_SIGNATURE_NOT_RECORDED = "issuer_signature (not recorded)"
_TOKEN_REPLAY_NOT_STORED = "token_replay (no token stored)"


class OidcJwtBindingVerifier:
    """Re-verifies recorded OIDC/JWT principal_binding blobs.

    `holder_jwk`, if supplied (at construction or per-call), is the holder's
    public key in JWK form -- offline trust material (DD-I3) used only to
    confirm a recorded `cnf.jkt` thumbprint matches a specific key. It is never
    used to verify a signature; this adapter has no token to verify a
    signature over.
    """

    scheme = "oidc-jwt"

    def __init__(self, *, holder_jwk: Mapping[str, Any] | None = None) -> None:
        self._holder_jwk = dict(holder_jwk) if holder_jwk is not None else None

    def handles(self, binding: dict[str, Any]) -> bool:
        """True when `binding` decodes to claims with an https `iss` and no
        SPIFFE-shaped marker (`trust_domain` / `spiffe_id`) -- declining
        cleanly on anything that is not OIDC-shaped, including malformed input,
        is what keeps the neutral Protocol from silently assuming OIDC."""
        claims = self._decode_claims(binding)
        if claims is None:
            return False
        iss = claims.get("iss")
        if not isinstance(iss, str) or not iss.startswith("https://"):
            return False
        return "trust_domain" not in claims and "spiffe_id" not in claims

    def verify(
        self,
        binding: dict[str, Any],
        *,
        at_time: datetime,
        expected_issuers: list[str] | None = None,
        expected_audience: str | None = None,
        holder_jwk: Mapping[str, Any] | None = None,
    ) -> BindingVerificationResult:
        checks_performed: list[str] = []
        checks_not_performed: list[str] = [
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
            if claims.get("aud") != expected_audience:
                failure_reasons.append(
                    f"audience {claims.get('aud')!r} != expected_audience {expected_audience!r}"
                )

        cnf = claims.get("cnf")
        if cnf is not None:
            checks_performed.append("cnf_jkt_format")
            self._check_cnf_jkt(cnf, holder_jwk, failure_reasons, checks_performed)

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
        iat, exp = claims.get("iat"), claims.get("exp")
        if not (isinstance(iat, int) and isinstance(exp, int)):
            if "iat" in claims or "exp" in claims:
                failure_reasons.append("iat/exp present but not well-formed integers")
            return
        at_epoch = int(at_time.timestamp())
        if not (iat <= at_epoch <= exp):
            failure_reasons.append(
                f"at_time {at_time.isoformat()} (epoch {at_epoch}) outside validity "
                f"window [iat={iat}, exp={exp}]"
            )

    def _check_cnf_jkt(
        self,
        cnf: Any,
        holder_jwk: Mapping[str, Any] | None,
        failure_reasons: list[str],
        checks_performed: list[str],
    ) -> None:
        jkt = cnf.get("jkt") if isinstance(cnf, Mapping) else None
        if not is_well_formed_thumbprint(jkt):
            failure_reasons.append("cnf.jkt is not a well-formed RFC 7638 SHA-256 thumbprint")
            return
        effective_holder = holder_jwk if holder_jwk is not None else self._holder_jwk
        if effective_holder is None:
            return
        checks_performed.append("cnf_jkt_holder_match")
        try:
            recomputed = compute_jwk_thumbprint(effective_holder)
        except ValueError as exc:
            failure_reasons.append(f"supplied holder_jwk could not be thumbprinted: {exc}")
            return
        if recomputed != jkt:
            failure_reasons.append("cnf.jkt does not match supplied holder_jwk thumbprint")

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
