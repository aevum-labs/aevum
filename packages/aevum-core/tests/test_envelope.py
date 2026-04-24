"""Tests for OutputEnvelope and sub-type models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aevum.core.envelope.models import OutputEnvelope, ProvenanceRecord

VALID_ID = "urn:aevum:audit:12345678-1234-7234-8234-123456789012"


def test_ok_envelope() -> None:
    env = OutputEnvelope.ok(audit_id=VALID_ID, data={"x": 1},
                            provenance=ProvenanceRecord.kernel(VALID_ID))
    assert env.status == "ok"
    assert env.review_required is False
    assert env.schema_version == "1.0"


def test_invalid_audit_id() -> None:
    with pytest.raises(ValidationError):
        OutputEnvelope.ok(audit_id="bad-id", data={},
                          provenance=ProvenanceRecord.kernel(VALID_ID))


def test_confidence_out_of_range() -> None:
    from aevum.core.envelope.models import (
        ReasoningTrace,
        SourceHealthSummary,
        UncertaintyAnnotation,
    )
    with pytest.raises(ValidationError):
        OutputEnvelope(status="ok", data={}, audit_id=VALID_ID, confidence=1.5,
                       uncertainty=UncertaintyAnnotation.empty(),
                       provenance=ProvenanceRecord.kernel(VALID_ID),
                       review_required=False,
                       source_health=SourceHealthSummary.no_complications(),
                       warnings=[], schema_version="1.0",
                       reasoning_trace=ReasoningTrace.empty())


def test_error_envelope() -> None:
    env = OutputEnvelope.error(audit_id=VALID_ID, error_code="consent_required",
                               error_detail="No grant",
                               provenance=ProvenanceRecord.kernel(VALID_ID))
    assert env.status == "error"
    assert env.confidence == 0.0
    assert env.data["error_code"] == "consent_required"


def test_crisis_envelope() -> None:
    env = OutputEnvelope.crisis(audit_id=VALID_ID, safe_message="Please reach out",
                                resources=["988"], provenance=ProvenanceRecord.kernel(VALID_ID))
    assert env.status == "crisis"
    assert env.confidence == 0.0
    assert "safe_message" in env.data


def test_classification_range() -> None:
    for level in (0, 1, 2, 3):
        p = ProvenanceRecord(source_id="s", ingest_audit_id=VALID_ID,
                             chain_of_custody=["s"], classification=level)
        assert p.classification == level

    with pytest.raises(ValidationError):
        ProvenanceRecord(source_id="s", ingest_audit_id=VALID_ID,
                         chain_of_custody=["s"], classification=4)
