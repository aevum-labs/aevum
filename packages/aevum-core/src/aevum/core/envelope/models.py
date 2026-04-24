"""
OutputEnvelope — the mandatory return type of all five functions.
Spec Section 05.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator


class UncertaintyAnnotation(BaseModel):
    model_config = ConfigDict(frozen=True)
    sources: list[str]
    missing_context: list[str]
    assumptions: list[str]
    confidence_basis: str

    @classmethod
    def empty(cls) -> UncertaintyAnnotation:
        return cls(sources=[], missing_context=[], assumptions=[], confidence_basis="none")


class ProvenanceRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    source_id: str
    ingest_audit_id: str
    chain_of_custody: list[str]
    classification: int
    model_id: str | None = None

    @field_validator("classification")
    @classmethod
    def classification_valid(cls, v: int) -> int:
        if v not in (0, 1, 2, 3):
            raise ValueError(f"classification must be 0-3, got {v}")
        return v

    @classmethod
    def kernel(cls, audit_id: str) -> ProvenanceRecord:
        return cls(
            source_id="aevum-core",
            ingest_audit_id=audit_id,
            chain_of_custody=["aevum-core"],
            classification=0,
        )


class ReviewContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    proposed_action: str
    reason: str
    deadline: datetime | None = None
    autonomy_level: int
    risk_assessment: str


class SourceHealthSummary(BaseModel):
    model_config = ConfigDict(frozen=True)
    available: list[str]
    degraded: list[str]
    unavailable: list[str]
    overall: Literal["healthy", "degraded", "critical"]

    @classmethod
    def no_complications(cls) -> SourceHealthSummary:
        return cls(available=[], degraded=[], unavailable=[], overall="healthy")


class ReasoningStep(BaseModel):
    model_config = ConfigDict(frozen=True)
    step_id: str
    description: str
    inputs: list[str]
    output_summary: str
    duration_ms: int


class ReasoningTrace(BaseModel):
    model_config = ConfigDict(frozen=True)
    steps: list[ReasoningStep]
    total_duration_ms: int

    @classmethod
    def empty(cls) -> ReasoningTrace:
        return cls(steps=[], total_duration_ms=0)


class OutputEnvelope(BaseModel):
    """The mandatory return type of all five functions. Spec Section 05."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "error", "pending_review", "degraded", "crisis"]
    data: dict[str, Any]
    audit_id: str
    confidence: float
    uncertainty: UncertaintyAnnotation
    provenance: ProvenanceRecord
    review_required: bool
    review_context: ReviewContext | None = None
    source_health: SourceHealthSummary
    warnings: list[str]
    schema_version: str = "1.0"
    reasoning_trace: ReasoningTrace

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {v}")
        return v

    @field_validator("audit_id")
    @classmethod
    def audit_id_is_urn(cls, v: str) -> str:
        if not v.startswith("urn:aevum:audit:"):
            raise ValueError(f"audit_id must start with 'urn:aevum:audit:', got {v!r}")
        return v

    @field_validator("schema_version")
    @classmethod
    def schema_version_known(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(f"Unknown schema_version: {v!r}")
        return v

    @classmethod
    def ok(
        cls,
        *,
        audit_id: str,
        data: dict[str, Any],
        confidence: float = 0.9,
        provenance: ProvenanceRecord,
        warnings: list[str] | None = None,
    ) -> OutputEnvelope:
        return cls(
            status="ok",
            data=data,
            audit_id=audit_id,
            confidence=confidence,
            uncertainty=UncertaintyAnnotation.empty(),
            provenance=provenance,
            review_required=False,
            source_health=SourceHealthSummary.no_complications(),
            warnings=warnings or [],
            reasoning_trace=ReasoningTrace.empty(),
        )

    @classmethod
    def error(
        cls,
        *,
        audit_id: str,
        error_code: str,
        error_detail: str,
        provenance: ProvenanceRecord,
    ) -> OutputEnvelope:
        return cls(
            status="error",
            data={"error_code": error_code, "error_detail": error_detail},
            audit_id=audit_id,
            confidence=0.0,
            uncertainty=UncertaintyAnnotation.empty(),
            provenance=provenance,
            review_required=False,
            source_health=SourceHealthSummary.no_complications(),
            warnings=[],
            reasoning_trace=ReasoningTrace.empty(),
        )

    @classmethod
    def crisis(
        cls,
        *,
        audit_id: str,
        safe_message: str,
        resources: list[str],
        provenance: ProvenanceRecord,
    ) -> OutputEnvelope:
        return cls(
            status="crisis",
            data={"safe_message": safe_message, "resources": resources},
            audit_id=audit_id,
            confidence=0.0,
            uncertainty=UncertaintyAnnotation.empty(),
            provenance=provenance,
            review_required=False,
            source_health=SourceHealthSummary.no_complications(),
            warnings=[],
            reasoning_trace=ReasoningTrace.empty(),
        )

    @classmethod
    def pending_review(
        cls,
        *,
        audit_id: str,
        review_context: ReviewContext,
        provenance: ProvenanceRecord,
    ) -> OutputEnvelope:
        return cls(
            status="pending_review",
            data={},
            audit_id=audit_id,
            confidence=0.0,
            uncertainty=UncertaintyAnnotation.empty(),
            provenance=provenance,
            review_required=True,
            review_context=review_context,
            source_health=SourceHealthSummary.no_complications(),
            warnings=[],
            reasoning_trace=ReasoningTrace.empty(),
        )
