"""ConsentGrant — the unit of permission. Spec Section 07.2."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

VALID_OPERATIONS = frozenset({"ingest", "query", "replay", "export"})


class ConsentGrant(BaseModel):
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
