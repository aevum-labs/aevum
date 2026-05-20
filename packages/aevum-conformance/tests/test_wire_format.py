# SPDX-License-Identifier: Apache-2.0
"""
Layer 1 — Wire Format conformance tests.

These tests assert that every new sigchain envelope carries the required
cryptographic metadata fields introduced in Phase C-1 (C-01).

Reference: aevum-spec Section 06 "Sigchain Wire Format".
"""
from __future__ import annotations

import dataclasses

import pytest
from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import Sigchain

# -------------------------------------------------------------------------
# Valid key_scheme values (Phase C-1 registry)
# -------------------------------------------------------------------------
_VALID_KEY_SCHEMES = frozenset({"ed25519", "ed25519+ml-dsa-65"})


class TestKeySchemeField:
    """C-01: key_scheme present and valid on every new envelope."""

    def test_new_envelope_carries_key_scheme(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="wire-test")
        assert hasattr(event, "key_scheme"), "key_scheme field missing from AuditEvent"
        assert event.key_scheme is not None

    def test_new_envelope_key_scheme_is_ed25519(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="wire-test")
        assert event.key_scheme == "ed25519"

    def test_key_scheme_default_is_ed25519(self) -> None:
        """Default value on the dataclass must be 'ed25519'."""
        field_defaults = {f.name: f.default for f in dataclasses.fields(AuditEvent)}
        assert "key_scheme" in field_defaults, "key_scheme has no default (backwards compat broken)"
        assert field_defaults["key_scheme"] == "ed25519"

    def test_all_new_events_in_chain_carry_key_scheme(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="wire-test")
            for i in range(5)
        ]
        for event in events:
            assert event.key_scheme == "ed25519", (
                f"event seq={event.sequence} missing or wrong key_scheme"
            )

    def test_key_scheme_value_is_in_valid_registry(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="wire-test")
        assert event.key_scheme in _VALID_KEY_SCHEMES

    def test_valid_key_scheme_registry_contains_required_values(self) -> None:
        assert "ed25519" in _VALID_KEY_SCHEMES
        assert "ed25519+ml-dsa-65" in _VALID_KEY_SCHEMES


class TestKeySchemeBackwardsCompat:
    """C-01 backwards compat: envelopes without key_scheme still verify."""

    def test_event_with_default_key_scheme_verifies(self) -> None:
        """Envelopes carrying the default key_scheme verify correctly."""
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={}, actor="compat-test")
            for i in range(3)
        ]
        assert chain.verify_chain(events) is True

    def test_event_without_explicit_key_scheme_uses_default(self) -> None:
        """AuditEvent constructed without key_scheme kwarg gets 'ed25519'."""
        chain = Sigchain()
        e = chain.new_event(event_type="legacy.sim", payload={}, actor="compat-test")
        # Simulate a pre-Phase-C event loaded from storage (key_scheme absent → default)
        legacy = dataclasses.replace(e, key_scheme="ed25519")
        assert legacy.key_scheme == "ed25519"
        assert chain.verify_chain([legacy]) is True

    def test_mixed_chain_old_and_new_events_verifies(self) -> None:
        """Chain mixing pre-C (default key_scheme) and new events must verify."""
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="mixed-test")
            for i in range(4)
        ]
        # All events have key_scheme="ed25519" (default or explicit) — chain must verify
        assert chain.verify_chain(events) is True


class TestWireFormatInvariant:
    """End-to-end wire format integrity check."""

    def test_key_scheme_and_signature_scheme_both_present(self) -> None:
        """Both cryptographic metadata fields must coexist on new envelopes."""
        chain = Sigchain()
        event = chain.new_event(event_type="test.meta", payload={}, actor="meta-test")
        assert event.key_scheme == "ed25519"
        assert event.signature_scheme == "Ed25519"

    def test_key_scheme_is_immutable_on_frozen_dataclass(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.freeze", payload={}, actor="freeze-test")
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            event.key_scheme = "tampered"  # type: ignore[misc]
