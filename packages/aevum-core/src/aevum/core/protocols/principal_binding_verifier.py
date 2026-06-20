# SPDX-License-Identifier: Apache-2.0
"""
PrincipalBindingVerifier -- neutral Protocol for re-verifying a recorded v2
principal_binding (P2-IDENTITY-V2, spec docs/spec/aevum-signing-v2.md).

A v2 AuditEvent's `principal_binding` field is an allow-list-extracted, opaque
blob built from already-verified credential claims at COMMIT time (DD7) --
chain integrity verification (DD6) never needs to interpret it. A binding
verifier re-examines that recorded blob LATER, independent of chain
verification, to check it is well-formed and consistent with a policy
(expected issuer, expected audience, validity window) -- it is a witness-model
consistency check, not a re-issuance of the original credential's signature.

This module defines only the SHAPE of that check, with zero OIDC/SPIFFE/JWKS
imports -- exactly as protocols/audit_ledger.py defines the ledger shape
without depending on any concrete backend. `aevum-oidc` (OIDC/JWT) and
`aevum-spiffe` (future SPIFFE-side verifier) both implement this Protocol
without aevum-core depending on either.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime


@dataclasses.dataclass(frozen=True)
class BindingVerificationResult:
    """Outcome of re-verifying a recorded principal_binding blob.

    `checks_performed` / `checks_not_performed` make the verification's scope
    structural rather than merely documented (the HONESTY SCOPE requirement) --
    a caller can inspect the result and see exactly what was and was not
    checked, rather than relying on a docstring elsewhere.
    """

    verified: bool
    scheme: str
    checks_performed: list[str]
    checks_not_performed: list[str]
    failure_reasons: list[str]


@runtime_checkable
class PrincipalBindingVerifier(Protocol):
    """Issuer-neutral contract for re-verifying a recorded principal_binding blob.

    `scheme` identifies which binding shape this verifier understands (e.g.
    "oidc-jwt"). `handles()` lets a caller holding several verifiers pick the
    right one for a given binding without assuming any particular scheme.
    """

    scheme: str

    def handles(self, binding: dict[str, Any]) -> bool: ...

    def verify(
        self,
        binding: dict[str, Any],
        *,
        at_time: datetime,
        expected_issuers: list[str] | None = None,
        expected_audience: str | None = None,
    ) -> BindingVerificationResult: ...
