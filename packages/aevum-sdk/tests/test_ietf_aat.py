"""Tests for IETF Agent Audit Trail export adapter."""

from __future__ import annotations

from aevum.core.audit.event import AuditEvent

from aevum.sdk.export.ietf_aat import (
    _IETF_GENESIS_HASH,
    _jcs_dumps,
    _sha256_jcs,
    export_audit_event,
    export_sigchain,
)


def _make_event(sequence: int = 1, event_type: str = "ingest.accepted") -> AuditEvent:
    payload: dict = {"note": f"event-{sequence}"}
    return AuditEvent(
        event_id=f"01234567-0000-7000-8000-{sequence:012d}",
        episode_id="01234567-0000-7000-8000-000000000099",
        sequence=sequence,
        event_type=event_type,
        schema_version="1.0",
        valid_from="2026-05-01T00:00:00Z",
        valid_to=None,
        system_time=1_000_000_000 + sequence,
        causation_id=None,
        correlation_id=None,
        actor="test-agent",
        trace_id=None,
        span_id=None,
        payload=payload,
        payload_hash=AuditEvent.hash_payload(payload),
        prior_hash="aevum:genesis",
        signature="AAAA",
        signer_key_id="key-1",
    )


def test_jcs_is_deterministic() -> None:
    obj = {"b": 2, "a": 1, "c": {"z": 26, "m": 13}}
    result1 = _jcs_dumps(obj)
    result2 = _jcs_dumps(obj)
    assert result1 == result2


def test_jcs_sorts_keys() -> None:
    obj = {"z": 1, "a": 2}
    canonical = _jcs_dumps(obj).decode()
    assert canonical.index('"a"') < canonical.index('"z"')


def test_sha256_jcs_format() -> None:
    obj = {"test": "value"}
    result = _sha256_jcs(obj)
    assert result.startswith("sha256:")
    assert len(result) == 7 + 64  # "sha256:" + 64 hex chars


def test_export_audit_event_mandatory_fields() -> None:
    event = _make_event()
    record = export_audit_event(event)
    for field in ("agent_id", "action_type", "outcome", "timestamp", "prior_hash"):
        assert field in record, f"Mandatory IETF field missing: {field}"


def test_export_audit_event_outcome_success() -> None:
    event = _make_event(event_type="ingest.accepted")
    record = export_audit_event(event)
    assert record["outcome"] == "success"


def test_export_audit_event_outcome_failure() -> None:
    event = _make_event(event_type="ingest.barrier_crisis")
    record = export_audit_event(event)
    assert record["outcome"] == "failure"


def test_export_audit_event_aevum_extension_fields() -> None:
    event = _make_event()
    record = export_audit_event(event)
    assert record["aevum:audit_id"].startswith("urn:aevum:audit:")
    assert record["aevum:sequence"] == 1
    assert record["aevum:prior_hash_sha3"] == "aevum:genesis"


def test_export_sigchain_hash_chain_is_valid() -> None:
    events = [_make_event(i) for i in range(1, 4)]
    records = export_sigchain(events)
    assert len(records) == 3

    # First record must reference genesis
    assert records[0]["prior_hash"] == _IETF_GENESIS_HASH

    # Each record's chain_hash must match what the next record references
    for i in range(len(records) - 1):
        expected_next_prior = records[i]["chain_hash"]
        actual_next_prior = records[i + 1]["prior_hash"]
        assert expected_next_prior == actual_next_prior, \
            f"Chain broken between record {i} and {i+1}"


def test_export_sigchain_empty_returns_empty() -> None:
    assert export_sigchain([]) == []


def test_export_sigchain_single_event() -> None:
    records = export_sigchain([_make_event(1)])
    assert len(records) == 1
    assert records[0]["prior_hash"] == _IETF_GENESIS_HASH
    assert "chain_hash" in records[0]


def test_chain_hash_changes_when_content_changes() -> None:
    event_a = _make_event(1, event_type="ingest.accepted")
    event_b = _make_event(1, event_type="ingest.barrier_crisis")
    records_a = export_sigchain([event_a])
    records_b = export_sigchain([event_b])
    assert records_a[0]["chain_hash"] != records_b[0]["chain_hash"]
