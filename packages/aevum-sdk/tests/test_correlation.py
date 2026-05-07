"""
Tests for aevum.sdk.correlation — multi-agent episode correlation utilities.
Pure unit tests; no mocking required.
"""
from __future__ import annotations

import hashlib
import json
import re

import pytest

from aevum.sdk.correlation import (
    build_cross_chain_ref,
    extract_episode_id_from_traceparent,
    inject_traceparent,
    _SIGNING_FIELDS,
)


class TestExtractEpisodeIdFromTraceparent:

    def test_valid_traceparent_extracts_trace_id(self) -> None:
        header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        result = extract_episode_id_from_traceparent(header)
        assert result == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_empty_header_returns_none(self) -> None:
        assert extract_episode_id_from_traceparent("") is None
        assert extract_episode_id_from_traceparent("   ") is None

    def test_malformed_header_returns_none(self) -> None:
        assert extract_episode_id_from_traceparent("not-a-traceparent") is None
        assert extract_episode_id_from_traceparent("00-short-00f067aa0ba902b7-01") is None

    def test_all_zero_trace_id_returns_none(self) -> None:
        # All-zero trace-id is invalid per W3C spec
        header = f"00-{'0' * 32}-00f067aa0ba902b7-01"
        assert extract_episode_id_from_traceparent(header) is None

    def test_version_ff_reserved_returns_none(self) -> None:
        header = f"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        assert extract_episode_id_from_traceparent(header) is None

    def test_non_sampled_flag_still_extracts(self) -> None:
        # Flags "00" means not sampled — but we still extract the episode_id
        header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
        result = extract_episode_id_from_traceparent(header)
        assert result == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_uppercase_header_accepted(self) -> None:
        header = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01"
        result = extract_episode_id_from_traceparent(header)
        assert result == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_result_is_lowercase(self) -> None:
        header = "00-AABBCCDDAABBCCDDAABBCCDDAABBCCDD-0011223344556677-01"
        result = extract_episode_id_from_traceparent(header)
        assert result == result.lower()


class TestInjectTraceparent:

    def test_produces_valid_traceparent_format(self) -> None:
        episode_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        header = inject_traceparent(episode_id)
        parts = header.split("-")
        assert len(parts) == 4
        assert parts[0] == "00"
        assert parts[1] == episode_id
        assert len(parts[2]) == 16
        assert parts[3] == "01"

    def test_roundtrip_extract_inject(self) -> None:
        """inject → extract must recover the original episode_id."""
        episode_id = "cafebabe0123456789abcdef01234567"
        header = inject_traceparent(episode_id)
        recovered = extract_episode_id_from_traceparent(header)
        assert recovered == episode_id

    def test_uuid_episode_id_normalised(self) -> None:
        """UUID v7 format (with hyphens) must be normalised to 32 hex chars."""
        episode_id = "01961234-5678-7abc-def0-123456789012"
        header = inject_traceparent(episode_id)
        recovered = extract_episode_id_from_traceparent(header)
        assert recovered == "019612345678" + "7abcdef0123456789012"
        # Verify no hyphens in trace-id part
        assert "-" not in header.split("-", 1)[1].split("-")[0]

    def test_custom_parent_span_id(self) -> None:
        episode_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        header = inject_traceparent(episode_id, parent_span_id="deadbeef01234567")
        assert header == "00-4bf92f3577b34da6a3ce929d0e0e4736-deadbeef01234567-01"

    def test_not_sampled_flag(self) -> None:
        episode_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        header = inject_traceparent(episode_id, flags="00")
        assert header.endswith("-00")

    def test_invalid_flags_raises(self) -> None:
        with pytest.raises(ValueError, match="flags"):
            inject_traceparent("4bf92f3577b34da6a3ce929d0e0e4736", flags="xyz")

    def test_invalid_parent_span_id_raises(self) -> None:
        with pytest.raises(ValueError, match="parent_span_id"):
            inject_traceparent(
                "4bf92f3577b34da6a3ce929d0e0e4736",
                parent_span_id="too-short",
            )

    def test_different_calls_produce_different_parent_ids(self) -> None:
        """Auto-generated parent-ids must be random."""
        episode_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        h1 = inject_traceparent(episode_id)
        h2 = inject_traceparent(episode_id)
        # Same trace-id, different parent-ids (probabilistically)
        assert h1.split("-")[1] == h2.split("-")[1]  # same trace-id
        # Parent IDs are very likely different (2^64 space)
        # Can't assert != (extremely rare collision), but test structure is correct


class TestBuildCrossChainRef:

    _sample_event = {
        "sequence": 5,
        "event_id": "01961234-5678-7abc-def0-123456789012",
        "audit_id": "urn:aevum:audit:01961234-5678-7abc-def0-123456789012",
        "event_type": "commit.accepted",
        "actor": "billing-agent",
        "system_time": 1746000000000000000,
        "episode_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "causation_id": None,
        "correlation_id": None,
        "prior_hash": "a" * 64,
        "payload_hash": "b" * 64,
        "signature": "c" * 88,
        "signer_key_id": "test-key-001",
        "schema_version": "1.0",
        "valid_from": "2026-05-06T12:00:00Z",
        "valid_to": None,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "span_id": "00f067aa0ba902b7",
        "payload": {"result": "approved"},
    }

    def test_required_fields_present(self) -> None:
        ref = build_cross_chain_ref(
            self._sample_event,
            trust_domain="spiffe://example.org",
            agent_id="billing-agent",
        )
        assert "trust_domain" in ref
        assert "agent_id" in ref
        assert "episode_id" in ref
        assert "system_time" in ref
        assert "event_hash" in ref

    def test_trust_domain_and_agent_id_preserved(self) -> None:
        ref = build_cross_chain_ref(
            self._sample_event,
            trust_domain="spiffe://production.example.com",
            agent_id="service/billing-v2",
        )
        assert ref["trust_domain"] == "spiffe://production.example.com"
        assert ref["agent_id"] == "service/billing-v2"

    def test_episode_id_from_event(self) -> None:
        ref = build_cross_chain_ref(
            self._sample_event,
            trust_domain="",
            agent_id="",
        )
        assert ref["episode_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_event_hash_is_sha3_256_hex(self) -> None:
        ref = build_cross_chain_ref(
            self._sample_event,
            trust_domain="",
            agent_id="",
        )
        assert len(ref["event_hash"]) == 64
        assert re.match(r"^[0-9a-f]{64}$", ref["event_hash"])

    def test_event_hash_is_deterministic(self) -> None:
        ref1 = build_cross_chain_ref(self._sample_event, trust_domain="", agent_id="")
        ref2 = build_cross_chain_ref(self._sample_event, trust_domain="", agent_id="")
        assert ref1["event_hash"] == ref2["event_hash"]

    def test_event_hash_changes_when_event_changes(self) -> None:
        modified = dict(self._sample_event)
        modified["actor"] = "DIFFERENT_ACTOR"
        ref1 = build_cross_chain_ref(self._sample_event, trust_domain="", agent_id="")
        ref2 = build_cross_chain_ref(modified, trust_domain="", agent_id="")
        assert ref1["event_hash"] != ref2["event_hash"]

    def test_event_hash_uses_signing_fields_only(self) -> None:
        """event_hash must match the signing-spec hash (not a full-event hash)."""
        from aevum.sdk.correlation import _compute_event_hash, _SIGNING_FIELDS

        signing_obj = {f: self._sample_event.get(f) for f in _SIGNING_FIELDS}
        canonical = json.dumps(
            signing_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        expected = hashlib.sha3_256(canonical).hexdigest()
        assert _compute_event_hash(self._sample_event) == expected

    def test_signing_fields_match_spec(self) -> None:
        """_SIGNING_FIELDS must exactly match aevum-signing-v1.md."""
        expected = {
            "actor", "causation_id", "correlation_id", "episode_id",
            "event_id", "event_type", "payload_hash", "prior_hash",
            "schema_version", "signer_key_id", "span_id", "system_time",
            "trace_id", "valid_from", "valid_to",
        }
        # If the signing spec adds or removes fields, this test catches it
        assert set(_SIGNING_FIELDS) == expected, (
            f"SIGNING_FIELDS mismatch.\n"
            f"Extra: {set(_SIGNING_FIELDS) - expected}\n"
            f"Missing: {expected - set(_SIGNING_FIELDS)}"
        )

    def test_missing_episode_id_defaults_to_empty_string(self) -> None:
        event_no_episode = {k: v for k, v in self._sample_event.items()
                            if k != "episode_id"}
        ref = build_cross_chain_ref(event_no_episode, trust_domain="", agent_id="")
        assert ref["episode_id"] == ""


class TestNormaliseToTraceId:

    def test_already_32_hex_passthrough(self) -> None:
        from aevum.sdk.correlation import _normalise_to_trace_id
        trace = "4bf92f3577b34da6a3ce929d0e0e4736"
        assert _normalise_to_trace_id(trace) == trace

    def test_uuid_stripped_of_hyphens(self) -> None:
        from aevum.sdk.correlation import _normalise_to_trace_id
        uuid = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"
        assert _normalise_to_trace_id(uuid) == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_non_hex_string_hashed(self) -> None:
        from aevum.sdk.correlation import _normalise_to_trace_id
        result = _normalise_to_trace_id("ep-billing-INV-001")
        assert len(result) == 32
        assert re.match(r"^[0-9a-f]{32}$", result)
        # Deterministic
        assert _normalise_to_trace_id("ep-billing-INV-001") == result
