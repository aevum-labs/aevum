# SPDX-License-Identifier: Apache-2.0
"""P2k regression guard: JSON schema validates real engine entries; spec field list matches code.

Two invariants enforced here:

  1. SCHEMA REGRESSION GUARD — real AuditEvent entries produced by the engine
     (classical and hybrid) validate against docs/spec/aevum-event-v1.json.
     This catches schema drift: if a new field is added to AuditEvent without
     updating the schema, validation fails (additionalProperties: false).

  2. FIELD-LIST GUARD — the 19 signing fields documented in aevum-signing-v1.md
     exactly match the keys used by AuditEvent.hash_event_for_chain() (and by
     Sigchain.new_event / Sigchain.verify_chain, which share the same dict).
     This catches prose drift: if a field is added to the code without updating
     the spec, the test fails.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any
from unittest.mock import patch

import pytest
import rfc8785 as rfc8785_mod

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import Sigchain

try:
    from jsonschema import ValidationError, validate
    _HAS_JSONSCHEMA = True
except ImportError:
    _HAS_JSONSCHEMA = False

try:
    import oqs as _oqs_check  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_jsonschema = pytest.mark.skipif(not _HAS_JSONSCHEMA, reason="jsonschema not installed")
needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SPEC_DIR = pathlib.Path(__file__).parents[3] / "docs" / "spec"


def _load_schema() -> dict[str, Any]:
    schema_path = _SPEC_DIR / "aevum-event-v1.json"
    return json.loads(schema_path.read_text())  # type: ignore[no-any-return]


def _entry_dict(event: AuditEvent) -> dict[str, Any]:
    """Produce the JSON-serialisable dict that Engine.get_ledger_entries() returns.

    receipt_cbor is bytes | None; when bytes, hex-encode for JSON transport.
    """
    d = dataclasses.asdict(event)
    d["audit_id"] = event.audit_id()
    if isinstance(d.get("receipt_cbor"), bytes):
        d["receipt_cbor"] = d["receipt_cbor"].hex()
    return d


# ---------------------------------------------------------------------------
# Schema regression guard
# ---------------------------------------------------------------------------

class TestSchemaValidatesRealEntries:
    """Real engine-emitted entries must validate against aevum-event-v1.json."""

    @needs_jsonschema
    def test_classical_single_event_validates(self) -> None:
        """A classical (Ed25519-only) entry must validate against the schema."""
        schema = _load_schema()
        chain = Sigchain()
        event = chain.new_event(
            event_type="test.schema.classical",
            payload={"x": 1},
            actor="tester",
        )
        instance = _entry_dict(event)
        # Raises ValidationError on failure — no assertion needed, exception is the signal.
        validate(instance=instance, schema=schema)

    @needs_jsonschema
    def test_classical_multi_event_chain_validates(self) -> None:
        """All events in a multi-event chain must individually validate."""
        schema = _load_schema()
        chain = Sigchain()
        event_types = [
            "test.schema.classical.alpha",
            "test.schema.classical.beta",
            "test.schema.classical.gamma",
            "test.schema.classical.delta",
            "test.schema.classical.epsilon",
        ]
        for et in event_types:
            event = chain.new_event(event_type=et, payload={"et": et}, actor="tester")
            validate(instance=_entry_dict(event), schema=schema)

    @needs_jsonschema
    def test_entry_with_nullable_fields_validates(self) -> None:
        """Entries with null causation_id, trace_id, span_id, etc. must validate."""
        schema = _load_schema()
        chain = Sigchain()
        event = chain.new_event(
            event_type="test.schema.nullables",
            payload={},
            actor="aevum-core",
            causation_id=None,
            correlation_id=None,
            trace_id=None,
            span_id=None,
        )
        instance = _entry_dict(event)
        assert instance["causation_id"] is None
        assert instance["trace_id"] is None
        validate(instance=instance, schema=schema)

    @needs_jsonschema
    def test_entry_with_optional_fields_present_validates(self) -> None:
        """Entries with non-null causation_id and correlation_id must also validate."""
        schema = _load_schema()
        chain = Sigchain()
        event = chain.new_event(
            event_type="test.schema.optional_present",
            payload={"detail": "some data"},
            actor="tester",
            causation_id="urn:aevum:audit:01961234-5678-7abc-def0-123456789012",
            correlation_id="corr-abc-123",
        )
        validate(instance=_entry_dict(event), schema=schema)

    @needs_jsonschema
    @needs_liboqs
    def test_hybrid_entry_validates(self) -> None:
        """A hybrid (Ed25519 + ML-DSA-65) entry must validate against the schema."""
        from aevum.core.signing import DualSigner
        schema = _load_schema()
        chain = Sigchain(dual_signer=DualSigner.generate())
        event = chain.new_event(
            event_type="test.schema.hybrid",
            payload={"pqc": True},
            actor="tester",
        )
        instance = _entry_dict(event)
        assert instance["key_scheme"] == "ed25519+ml-dsa-65"
        assert instance["mldsa65_sig"] is not None
        assert instance["mldsa65_pub"] is not None
        validate(instance=instance, schema=schema)

    @needs_jsonschema
    def test_additional_properties_rejected(self) -> None:
        """additionalProperties: false must reject an entry with an unknown field."""
        schema = _load_schema()
        chain = Sigchain()
        event = chain.new_event(
            event_type="test.schema.addl",
            payload={},
            actor="tester",
        )
        instance = _entry_dict(event)
        instance["unknown_future_field"] = "should_fail"
        with pytest.raises(ValidationError, match="(?i)additional properties"):
            validate(instance=instance, schema=schema)

    @needs_jsonschema
    def test_missing_required_field_rejected(self) -> None:
        """Removing a required field must cause a validation error."""
        schema = _load_schema()
        chain = Sigchain()
        event = chain.new_event(event_type="test.schema.missing", payload={}, actor="tester")
        instance = _entry_dict(event)
        del instance["signature"]
        with pytest.raises(ValidationError):
            validate(instance=instance, schema=schema)


# ---------------------------------------------------------------------------
# Signing spec field-list guard
# ---------------------------------------------------------------------------

class TestSigningFieldListMatchesSpec:
    """The 19-field set in aevum-signing-v1.md must exactly match hash_event_for_chain."""

    # Authoritative set from aevum-signing-v1.md §"Signing Fields"
    SPEC_SIGNING_FIELDS: frozenset[str] = frozenset({
        "actor",
        "causation_id",
        "correlation_id",
        "episode_id",
        "event_id",
        "event_type",
        "hash_alg",
        "key_scheme",
        "payload_hash",
        "prior_hash",
        "schema_version",
        "sequence",
        "sig_format_version",
        "signer_key_id",
        "span_id",
        "system_time",
        "trace_id",
        "valid_from",
        "valid_to",
    })

    def _capture_hash_event_field_keys(self, event: AuditEvent) -> frozenset[str]:
        """Return the keys passed to rfc8785.dumps inside hash_event_for_chain."""
        captured: list[frozenset[str]] = []
        original = rfc8785_mod.dumps

        def capturing(fields: dict[str, Any]) -> bytes:
            captured.append(frozenset(fields.keys()))
            return original(fields)

        with patch.object(rfc8785_mod, "dumps", side_effect=capturing):
            AuditEvent.hash_event_for_chain(event)

        assert len(captured) == 1, (
            "hash_event_for_chain must call rfc8785.dumps exactly once"
        )
        return captured[0]

    def test_hash_event_for_chain_uses_spec_fields(self) -> None:
        """hash_event_for_chain must use exactly the 19 spec-documented signing fields."""
        chain = Sigchain()
        event = chain.new_event(
            event_type="spec.field_guard",
            payload={"guard": True},
            actor="spec-checker",
        )
        actual_keys = self._capture_hash_event_field_keys(event)
        assert actual_keys == self.SPEC_SIGNING_FIELDS, (
            f"Signing field mismatch between spec and code.\n"
            f"  In spec but not code: {self.SPEC_SIGNING_FIELDS - actual_keys}\n"
            f"  In code but not spec: {actual_keys - self.SPEC_SIGNING_FIELDS}"
        )

    def test_spec_has_exactly_19_fields(self) -> None:
        """The spec must document exactly 19 signing fields."""
        assert len(self.SPEC_SIGNING_FIELDS) == 19

    def test_system_time_not_a_signing_field_as_int(self) -> None:
        """system_time in the signing field set must be encoded as a string, not int.

        This guards the safe-integer rule: HLC values exceed 2^53-1. The
        rfc8785.dumps call inside hash_event_for_chain must receive system_time
        as a str, not the raw int.
        """
        captured_values: list[dict[str, Any]] = []
        original = rfc8785_mod.dumps

        def capturing(fields: dict[str, Any]) -> bytes:
            captured_values.append(dict(fields))
            return original(fields)

        chain = Sigchain()
        event = chain.new_event(event_type="spec.systime_type", payload={}, actor="a")

        with patch.object(rfc8785_mod, "dumps", side_effect=capturing):
            AuditEvent.hash_event_for_chain(event)

        assert len(captured_values) == 1
        systime_val = captured_values[0]["system_time"]
        assert isinstance(systime_val, str), (
            f"system_time must be encoded as str in signing fields, got {type(systime_val)}"
        )
        # Must be the decimal string of the raw integer
        assert systime_val == str(event.system_time)

    def test_non_signing_fields_absent(self) -> None:
        """payload, signature, mldsa65_sig, receipt_cbor, audit_id must NOT be signing fields."""
        chain = Sigchain()
        event = chain.new_event(event_type="spec.non_signing", payload={"x": 1}, actor="a")
        actual_keys = self._capture_hash_event_field_keys(event)
        for excluded in ("payload", "signature", "mldsa65_sig", "mldsa65_pub",
                         "tsa_url", "tsa_token", "receipt_cbor", "audit_id"):
            assert excluded not in actual_keys, (
                f"Field '{excluded}' must NOT appear in the signing field set"
            )
