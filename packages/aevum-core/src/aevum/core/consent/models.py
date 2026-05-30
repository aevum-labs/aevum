# SPDX-License-Identifier: Apache-2.0
"""ConsentGrant — the immutable consent decision record. Spec Section 07.2.

A ConsentGrant captures a single consent decision: subject S grants grantee G permission
to perform operations O on their data for purpose P until expires_at. Each grant is uniquely
identified by grant_id so it can be individually revoked without affecting other grants.

Purpose-specificity is validated at construction: vague purposes like "any" or "all" are
rejected, enforcing GDPR Art. 7(1) which requires consent to be specific and informed.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

# VALID_OPERATIONS is the closed set of operations that can appear in a ConsentGrant.
# Adding a new operation here requires a corresponding update to barriers.py check_consent()
# and to the Cedar policy that evaluates consent grants at query time.
VALID_OPERATIONS = frozenset({"ingest", "query", "replay", "export"})


class ConsentGrant(BaseModel):
    """Immutable consent grant record. Frozen so it cannot be altered after construction.

    Fields:
        grant_id:          Unique identifier — used for individual revocation.
        subject_id:        The data subject who is granting consent.
        grantee_id:        The principal (agent, user, service) receiving access.
        operations:        List of permitted operations (subset of VALID_OPERATIONS).
        purpose:           Specific, auditable purpose statement — vague values rejected.
        classification_max: Maximum data classification level accessible under this grant.
        granted_at:        ISO 8601 timestamp when consent was given.
        expires_at:        ISO 8601 expiry — grants do not auto-renew; must be re-issued.
        authorization_ref: Optional reference to an external legal basis document.
        revocation_status: "active", "revoked", or "expired" — lifecycle state.
    """
    model_config = ConfigDict(frozen=True)
    grant_id: str
    subject_id: str
    grantee_id: str
    operations: list[str]
    purpose: str
    classification_max: int
    granted_at: str
    expires_at: str
    authorization_ref: str | None = None
    revocation_status: Literal["active", "revoked", "expired"] = "active"

    @field_validator("operations")
    @classmethod
    def operations_valid(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("operations must be a non-empty list")
        invalid = set(v) - VALID_OPERATIONS
        if invalid:
            raise ValueError(f"Invalid operations: {invalid}. Must be subset of {sorted(VALID_OPERATIONS)}")
        return v

    @field_validator("purpose")
    @classmethod
    def purpose_specific(cls, v: str) -> str:
        if v.lower() in ("any", "all", "all purposes", "any purpose", ""):
            raise ValueError("purpose must be specific and auditable")
        return v

    @field_validator("classification_max")
    @classmethod
    def classification_valid(cls, v: int) -> int:
        if v not in (0, 1, 2, 3):
            raise ValueError(f"classification_max must be 0-3, got {v}")
        return v
