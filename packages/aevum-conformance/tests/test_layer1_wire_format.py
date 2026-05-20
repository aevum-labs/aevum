# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Layer 1 — Wire Format conformance tests.

These tests assert that every new sigchain envelope produced by Aevum
carries the key_scheme field and that the field takes a declared value.
They also verify that pre-Phase-C envelopes (schema_version "1.0",
key_scheme absent / defaulted) continue to verify correctly.
"""
from __future__ import annotations

import dataclasses

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import Sigchain

VALID_KEY_SCHEMES = {"ed25519", "ed25519+ml-dsa-65"}


class TestKeySchemePresent:
    """New envelopes must carry a key_scheme field."""

    def test_new_event_has_key_scheme(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert hasattr(event, "key_scheme"), "AuditEvent must have key_scheme attribute"

    def test_new_event_key_scheme_not_empty(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.key_scheme, "key_scheme must not be empty"

    def test_new_event_key_scheme_declared_value(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.key_scheme in VALID_KEY_SCHEMES, (
            f"key_scheme {event.key_scheme!r} is not a declared value; "
            f"expected one of {VALID_KEY_SCHEMES}"
        )

    def test_new_event_default_key_scheme_is_ed25519(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.key_scheme == "ed25519"

    def test_multiple_events_all_have_key_scheme(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"test.{i}", payload={"i": i}, actor="a")
            for i in range(5)
        ]
        for event in events:
            assert event.key_scheme in VALID_KEY_SCHEMES


class TestKeySchemeSchemaVersion:
    """New envelopes must use schema_version '1.1' which binds key_scheme."""

    def test_new_event_schema_version_is_1_1(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.schema_version == "1.1", (
            f"Expected schema_version '1.1', got {event.schema_version!r}. "
            "Phase C-1 requires schema_version '1.1' to bind key_scheme."
        )

    def test_key_scheme_included_in_chain_hash(self) -> None:
        """hash_event_for_chain() must include key_scheme for 1.1 events."""
        chain = Sigchain()
        e1 = chain.new_event(event_type="test.a", payload={}, actor="a")
        e2 = chain.new_event(event_type="test.b", payload={}, actor="a")

        # e2.prior_hash must equal hash_event_for_chain(e1) (which includes key_scheme)
        assert e2.prior_hash == AuditEvent.hash_event_for_chain(e1)

    def test_tampering_key_scheme_breaks_chain(self) -> None:
        """Modifying key_scheme on a 1.1 event invalidates the chain hash."""
        chain = Sigchain()
        e1 = chain.new_event(event_type="test.a", payload={}, actor="a")
        e2 = chain.new_event(event_type="test.b", payload={}, actor="a")

        # Tamper key_scheme on e1 — prior_hash in e2 must no longer match
        tampered = dataclasses.replace(e1, key_scheme="ed25519+ml-dsa-65")
        assert AuditEvent.hash_event_for_chain(tampered) != e2.prior_hash

    def test_verify_chain_passes_for_new_events(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"test.{i}", payload={"i": i}, actor="a")
            for i in range(4)
        ]
        assert chain.verify_chain(events) is True


class TestBackwardsCompatibility:
    """Pre-Phase-C envelopes (schema_version '1.0') must still verify correctly."""

    def _make_pre_phase_c_event(self, chain: Sigchain) -> AuditEvent:
        """
        Simulate a pre-Phase-C event by creating a 1.1 event then forcing it
        back to schema_version '1.0' with no key_scheme in the signing fields.
        We do this by replaying the signing logic from the 1.0 era.
        """
        import base64
        import hashlib
        import json

        from aevum.core.audit.sigchain import GENESIS_HASH

        seq = 1
        actor = "test-actor"
        event_type = "legacy.event"
        schema_ver = "1.0"
        payload: dict = {}
        payload_hash = AuditEvent.hash_payload(payload)
        prior = GENESIS_HASH
        episode_id = "legacy-ep"
        event_id = "00000000-0000-7000-8000-000000000001"
        system_time = 0
        vf = "2024-01-01T00:00:00+00:00"

        # Build signing_fields WITHOUT key_scheme (pre-Phase-C format)
        signing_fields = {
            "event_id": event_id,
            "episode_id": episode_id,
            "sequence": seq,
            "event_type": event_type,
            "schema_version": schema_ver,
            "valid_from": vf,
            "valid_to": None,
            "system_time": system_time,
            "causation_id": None,
            "correlation_id": None,
            "actor": actor,
            "trace_id": None,
            "span_id": None,
            "payload_hash": payload_hash,
            "prior_hash": prior,
            "signer_key_id": chain.key_id,
        }
        canonical = json.dumps(signing_fields, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha3_256(canonical).digest()
        from aevum.core.audit.signer import InProcessSigner
        inner: InProcessSigner = chain._signer  # type: ignore[assignment]
        sig_bytes = inner.sign(digest)
        signature = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

        return AuditEvent(
            event_id=event_id,
            episode_id=episode_id,
            sequence=seq,
            event_type=event_type,
            schema_version=schema_ver,  # "1.0" — no key_scheme in signed data
            valid_from=vf,
            valid_to=None,
            system_time=system_time,
            causation_id=None,
            correlation_id=None,
            actor=actor,
            trace_id=None,
            span_id=None,
            payload=payload,
            payload_hash=payload_hash,
            prior_hash=prior,
            signature=signature,
            signer_key_id=chain.key_id,
            # key_scheme defaults to "ed25519" — not in signed data
        )

    def test_pre_phase_c_event_has_default_key_scheme(self) -> None:
        chain = Sigchain()
        event = self._make_pre_phase_c_event(chain)
        assert event.key_scheme == "ed25519"
        assert event.schema_version == "1.0"

    def test_pre_phase_c_event_verifies_correctly(self) -> None:
        """verify_chain() must accept a pre-Phase-C event signed without key_scheme."""
        chain = Sigchain()
        # Force chain sequence/hash to match our hand-crafted event
        from aevum.core.audit.sigchain import GENESIS_HASH
        chain._sequence = 0
        chain._prior_hash = GENESIS_HASH

        event = self._make_pre_phase_c_event(chain)
        # Update chain state to reflect this legacy event
        chain._sequence = event.sequence
        chain._prior_hash = AuditEvent.hash_event_for_chain(event)

        assert chain.verify_chain([event]) is True

    def test_mixed_chain_1_0_then_1_1_verifies(self) -> None:
        """A chain with a 1.0 event followed by a 1.1 event must verify correctly."""
        chain = Sigchain()
        from aevum.core.audit.sigchain import GENESIS_HASH
        chain._sequence = 0
        chain._prior_hash = GENESIS_HASH

        legacy_event = self._make_pre_phase_c_event(chain)
        # Update sigchain state to chain off the legacy event
        chain._sequence = legacy_event.sequence
        chain._prior_hash = AuditEvent.hash_event_for_chain(legacy_event)

        # Now append a 1.1 event
        new_event = chain.new_event(event_type="new.event", payload={}, actor="a")
        assert new_event.schema_version == "1.1"
        assert new_event.key_scheme == "ed25519"

        # Full chain must verify
        assert chain.verify_chain([legacy_event, new_event]) is True
