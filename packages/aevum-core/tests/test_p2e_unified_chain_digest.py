# SPDX-License-Identifier: Apache-2.0
"""P2e gate tests: chain hash == signed digest (compute-once property).

After P2e, hash_event_for_chain for a fmt==1 entry covers the same 18 fields as
new_event()'s signing_fields, so the chain-link hash and the signed digest are
identical. This file proves that invariant directly and checks its consequences.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import GENESIS_HASH, Sigchain

try:
    import oqs as _oqs_check  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


def _signing_fields_18(event: AuditEvent) -> dict:
    """Reconstruct the 18-field canonical dict independently — mirrors new_event()'s signing_fields."""
    return {
        "event_id": event.event_id,
        "episode_id": event.episode_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
        "system_time": event.system_time,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "actor": event.actor,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "payload_hash": event.payload_hash,
        "prior_hash": event.prior_hash,
        "signer_key_id": event.signer_key_id,
        "key_scheme": event.key_scheme,
        "sig_format_version": 1,
    }


def _signing_fields_16(event: AuditEvent) -> dict:
    """Reconstruct the legacy 16-field canonical dict."""
    return {
        "event_id": event.event_id,
        "episode_id": event.episode_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
        "system_time": event.system_time,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "actor": event.actor,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "payload_hash": event.payload_hash,
        "prior_hash": event.prior_hash,
        "signer_key_id": event.signer_key_id,
    }


def _canonical_hex(fields: dict) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_256(canonical).hexdigest()


class TestComputeOnceProperty:
    """For fmt==1 entries the chain hash IS the signed digest — one canonical computation."""

    def test_classical_fmt1_chain_hash_equals_signed_digest(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="p2e.test", payload={"x": 1}, actor="a")
        assert event.sig_format_version == 1

        # Compute the expected digest independently from the 18 signing fields
        expected = _canonical_hex(_signing_fields_18(event))

        assert AuditEvent.hash_event_for_chain(event) == expected

    @needs_liboqs
    def test_hybrid_fmt1_chain_hash_equals_signed_digest(self) -> None:
        from aevum.core.signing import DualSigner
        chain = Sigchain(dual_signer=DualSigner.generate())
        event = chain.new_event(event_type="p2e.hybrid", payload={"x": 1}, actor="a")
        assert event.sig_format_version == 1
        assert event.key_scheme == "ed25519+ml-dsa-65"

        expected = _canonical_hex(_signing_fields_18(event))
        assert AuditEvent.hash_event_for_chain(event) == expected

    def test_compute_once_holds_for_multi_event_chain(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(4)
        ]
        for event in events:
            assert event.sig_format_version == 1
            expected = _canonical_hex(_signing_fields_18(event))
            assert AuditEvent.hash_event_for_chain(event) == expected


class TestKeySchemeNowBoundInChain:
    """key_scheme is now part of the chain hash — different schemes → different hashes."""

    def test_different_key_scheme_produces_different_chain_hash(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.sig_format_version == 1
        assert event.key_scheme == "ed25519"

        # Manufacture an event that is identical except for key_scheme
        hybrid = dataclasses.replace(event, key_scheme="ed25519+ml-dsa-65")

        h_classical = AuditEvent.hash_event_for_chain(event)
        h_hybrid = AuditEvent.hash_event_for_chain(hybrid)

        assert h_classical != h_hybrid, (
            "key_scheme must change the chain hash — it is now part of the signed field set"
        )

    def test_chain_hash_stable_for_same_event(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        h1 = AuditEvent.hash_event_for_chain(event)
        h2 = AuditEvent.hash_event_for_chain(event)
        assert h1 == h2


class TestLegacyFmt16FieldUnchanged:
    """Legacy fmt==None events still produce a 16-field chain hash."""

    def test_legacy_event_chain_hash_equals_16_field_digest(self) -> None:
        from test_p2a_sig_format_versioning import _build_legacy_event
        chain = Sigchain()
        event = _build_legacy_event(chain, sequence=1, prior_hash=GENESIS_HASH)
        assert event.sig_format_version is None

        expected = _canonical_hex(_signing_fields_16(event))
        assert AuditEvent.hash_event_for_chain(event) == expected

    def test_legacy_chain_hash_differs_from_18_field_hash(self) -> None:
        from test_p2a_sig_format_versioning import _build_legacy_event
        chain = Sigchain()
        event = _build_legacy_event(chain, sequence=1, prior_hash=GENESIS_HASH)
        assert event.sig_format_version is None

        hash_16 = _canonical_hex(_signing_fields_16(event))
        hash_18 = _canonical_hex(_signing_fields_18(event))
        # The two field sets differ (key_scheme + sig_format_version absent vs present),
        # so their digests must differ.
        assert hash_16 != hash_18
        assert AuditEvent.hash_event_for_chain(event) == hash_16

    def test_legacy_verify_chain_still_passes(self) -> None:
        from test_p2a_sig_format_versioning import _build_legacy_event
        chain = Sigchain()
        events: list[AuditEvent] = []
        prior = GENESIS_HASH
        for i in range(1, 4):
            e = _build_legacy_event(chain, sequence=i, prior_hash=prior, payload={"i": i})
            prior = AuditEvent.hash_event_for_chain(e)
            events.append(e)
        assert chain.verify_chain(events) is True


class TestEndToEndChainVerification:
    """End-to-end verify_chain passes for both classical and hybrid fmt==1 chains."""

    def test_classical_chain_verifies(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(5)
        ]
        assert chain.verify_chain(events) is True

    @needs_liboqs
    def test_hybrid_chain_verifies(self) -> None:
        from aevum.core.signing import DualSigner
        chain = Sigchain(dual_signer=DualSigner.generate())
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert all(e.key_scheme == "ed25519+ml-dsa-65" for e in events)
        assert chain.verify_chain(events) is True

    def test_prior_hash_linkage_uses_updated_chain_hash(self) -> None:
        """Second event's prior_hash must equal hash_event_for_chain of the first (18-field)."""
        chain = Sigchain()
        e1 = chain.new_event(event_type="t.1", payload={}, actor="a")
        e2 = chain.new_event(event_type="t.2", payload={}, actor="a")
        assert e2.prior_hash == AuditEvent.hash_event_for_chain(e1)
        # Also confirm this equals the 18-field independent computation
        assert e2.prior_hash == _canonical_hex(_signing_fields_18(e1))
