"""Pydantic models for the four-step sandbox endpoints."""

from typing import Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    model_config = {"json_schema_extra": {
        "example": {"host_id": "host-42", "scan_type": "diagnostic"}
    }}
    host_id: str = Field(
        description="The host identifier to scan.",
        examples=["host-42", "host-7", "host-prod-01"],
    )
    scan_type: Literal["diagnostic", "memory_pressure", "cert_check"] = Field(
        default="diagnostic",
        description="Type of scan to perform.",
    )


class ConsentRequest(BaseModel):
    task_id: str = Field(description="Task ID returned by /sandbox/scan")
    decision: Literal["approve", "deny"] = Field(
        description="Approve or deny the proposed remediation."
    )


class ExecuteRequest(BaseModel):
    task_id: str = Field(description="Task ID returned by /sandbox/scan")
    consent_token: str = Field(description="Consent token returned by /sandbox/consent")


# Response models

class ScanResult(BaseModel):
    task_id: str
    host_id: str
    finding: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    proposed_action: str
    barriers_evaluated: dict  # Crisis/Consent/ClassificationCeiling/AuditImmutability/Provenance
    receipt_hash: str


class ConsentResult(BaseModel):
    task_id: str
    decision: str
    consent_token: str
    valid_for_seconds: int


class ExecuteResult(BaseModel):
    task_id: str
    outcome: str
    sigchain_head: str   # SHA3-256 hex — the receipt hash
    rekor_entry: str     # "pending" in dev mode
    receipt_hash: str


class SigchainEntry(BaseModel):
    sequence: int
    action: str
    principal: str
    occurred_at: str
    sigchain_entry_hash: str
    handoff_type: str | None
    barrier_evaluations: dict


class SigchainResult(BaseModel):
    head_hash: str
    entry_count: int
    entries: list[SigchainEntry]
