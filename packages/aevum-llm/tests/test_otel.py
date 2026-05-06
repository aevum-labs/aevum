"""Tests for aevum.llm.otel — OTel GenAI attribute mapper."""

from __future__ import annotations

from aevum.core.audit.event import AuditEvent

from aevum.llm.otel import to_otel_attributes


def _make_event(**payload_overrides: object) -> AuditEvent:
    """Build a minimal AuditEvent for testing."""
    payload = {
        "gen_ai.request.model": "gpt-4.1",
        "gen_ai.response.model": "gpt-4.1-2026-04-14",
        "gen_ai.system": "openai",
        "gen_ai.operation.name": "chat",
        "prompt_hash": "abc123",
        "response_hash": "def456",
        **payload_overrides,
    }
    return AuditEvent(
        event_id="01234567-0000-7000-8000-000000000001",
        episode_id="01234567-0000-7000-8000-000000000002",
        sequence=1,
        event_type="llm.completion",
        schema_version="1.0",
        valid_from="2026-05-01T00:00:00Z",
        valid_to=None,
        system_time=1_000_000_000,
        causation_id=None,
        correlation_id=None,
        actor="billing-agent",
        trace_id=None,
        span_id=None,
        payload=payload,
        payload_hash=AuditEvent.hash_payload(payload),
        prior_hash="aevum:genesis",
        signature="AAAA",
        signer_key_id="key-1",
    )


def test_otel_attrs_contains_model_info() -> None:
    event = _make_event()
    attrs = to_otel_attributes(event)
    assert attrs["gen_ai.request.model"] == "gpt-4.1"
    assert attrs["gen_ai.response.model"] == "gpt-4.1-2026-04-14"
    assert attrs["gen_ai.system"] == "openai"
    assert attrs["gen_ai.operation.name"] == "chat"


def test_otel_attrs_contains_aevum_ids() -> None:
    event = _make_event()
    attrs = to_otel_attributes(event)
    assert attrs["aevum.audit_id"].startswith("urn:aevum:audit:")
    assert attrs["aevum.episode_id"] == event.episode_id
    assert attrs["aevum.actor"] == "billing-agent"


def test_otel_attrs_contains_hash_refs_not_content() -> None:
    event = _make_event()
    attrs = to_otel_attributes(event)
    assert attrs["aevum.gen_ai.prompt_hash"] == "abc123"
    assert attrs["aevum.gen_ai.response_hash"] == "def456"
    # Raw content must never appear
    assert "gen_ai.input.messages" not in attrs
    assert "gen_ai.output.messages" not in attrs
    assert "gen_ai.system_instructions" not in attrs


def test_otel_attrs_external_storage_reference() -> None:
    event = _make_event()
    attrs = to_otel_attributes(event)
    # audit_id IS the external storage reference
    assert attrs["gen_ai.content.reference"] == event.audit_id()


def test_otel_attrs_missing_model_info_is_graceful() -> None:
    payload: dict = {"prompt_hash": "abc"}
    e = AuditEvent(
        event_id="01234567-0000-7000-8000-000000000003",
        episode_id="01234567-0000-7000-8000-000000000004",
        sequence=1,
        event_type="ingest.accepted",
        schema_version="1.0",
        valid_from="2026-05-01T00:00:00Z",
        valid_to=None,
        system_time=1_000_000_000,
        causation_id=None,
        correlation_id=None,
        actor="agent",
        trace_id=None,
        span_id=None,
        payload=payload,
        payload_hash=AuditEvent.hash_payload(payload),
        prior_hash="aevum:genesis",
        signature="AAAA",
        signer_key_id="key-1",
    )
    attrs = to_otel_attributes(e)
    # Must not raise, must not include absent keys
    assert "gen_ai.request.model" not in attrs
    assert "aevum.audit_id" in attrs


def test_otel_attrs_all_values_are_primitive_types() -> None:
    event = _make_event()
    attrs = to_otel_attributes(event)
    for key, val in attrs.items():
        assert isinstance(val, (str, int, float, bool)), \
            f"Attribute {key!r} has non-primitive value: {type(val)}"
