# SPDX-License-Identifier: Apache-2.0
"""P2a tests: sig_format_version binding, verify_chain path splits, and back-compat."""
from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import json

import pytest

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.hlc import now as hlc_now
from aevum.core.audit.sigchain import GENESIS_HASH, Sigchain, _uuid7

try:
    import oqs as _oqs_check  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


def _build_legacy_event(
    chain: Sigchain,
    *,
    sequence: int,
    prior_hash: str,
    event_type: str = "legacy.event",
    payload: dict | None = None,
    actor: str = "tester",
) -> AuditEvent:
    """Synthetic pre-P2a entry: signed over exactly the original 16 fields.

    Mimics new_event() as it existed before P2a — no key_scheme or sig_format_version
    in signing_fields, and sig_format_version=None on the resulting AuditEvent.
    """
    if payload is None:
        payload = {}
    event_id = _uuid7()
    ep_id = _uuid7()
    vf = datetime.datetime.now(datetime.UTC).isoformat()
    ts = hlc_now()
    payload_hash = AuditEvent.hash_payload(payload)
    signing_fields = {
        "event_id": event_id,
        "episode_id": ep_id,
        "sequence": sequence,
        "event_type": event_type,
        "schema_version": "1.0",
        "valid_from": vf,
        "valid_to": None,
        "system_time": ts,
        "causation_id": None,
        "correlation_id": None,
        "actor": actor,
        "trace_id": None,
        "span_id": None,
        "payload_hash": payload_hash,
        "prior_hash": prior_hash,
        "signer_key_id": chain._signer.key_id,
    }
    canonical = json.dumps(signing_fields, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha3_256(canonical).digest()
    sig_bytes = chain._signer.sign(digest)
    signature = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    return AuditEvent(
        event_id=event_id,
        episode_id=ep_id,
        sequence=sequence,
        event_type=event_type,
        schema_version="1.0",
        valid_from=vf,
        valid_to=None,
        system_time=ts,
        causation_id=None,
        correlation_id=None,
        actor=actor,
        trace_id=None,
        span_id=None,
        payload=payload,
        payload_hash=payload_hash,
        prior_hash=prior_hash,
        signature=signature,
        signer_key_id=chain._signer.key_id,
        sig_format_version=None,
        # key_scheme defaults to "ed25519"
    )


class TestClassicalSigFormatVersion:
    """Classical (Ed25519-only) entries produced by new_event after P2a."""

    def test_sig_format_version_is_1(self) -> None:
        chain = Sigchain()
        e = chain.new_event(event_type="t", payload={}, actor="a")
        assert e.sig_format_version == 1

    def test_key_scheme_is_ed25519(self) -> None:
        chain = Sigchain()
        e = chain.new_event(event_type="t", payload={}, actor="a")
        assert e.key_scheme == "ed25519"

    def test_round_trip_verifies(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(5)
        ]
        assert chain.verify_chain(events) is True

    def test_strip_sig_format_version_fails(self) -> None:
        """Setting sig_format_version=None downgrades to legacy path; signing_fields mismatch → False."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        stripped = dataclasses.replace(event, sig_format_version=None)
        assert chain.verify_chain([stripped]) is False

    def test_mutate_key_scheme_fails(self) -> None:
        """key_scheme is bound in signing_fields; mutation → canonical mismatch → False."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        mutated = dataclasses.replace(event, key_scheme="ed25519+ml-dsa-65")
        assert chain.verify_chain([mutated]) is False

    def test_unknown_key_scheme_in_v1_entry_fails(self) -> None:
        """Unknown scheme on a versioned entry must not fall back silently."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        mutated = dataclasses.replace(event, key_scheme="rsa-4096")
        assert chain.verify_chain([mutated]) is False

    def test_unknown_sig_format_version_fails(self) -> None:
        """Future format version (e.g. 99) must fail closed — this verifier cannot validate it."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        future = dataclasses.replace(event, sig_format_version=99)
        assert chain.verify_chain([future]) is False


class TestSyntheticLegacyBackCompat:
    """D-C: synthetic pre-P2a entries (sig_format_version=None) must still verify."""

    def test_single_legacy_event_verifies(self) -> None:
        chain = Sigchain()
        event = _build_legacy_event(chain, sequence=1, prior_hash=GENESIS_HASH)
        assert chain.verify_chain([event]) is True

    def test_legacy_event_has_sig_format_version_none(self) -> None:
        chain = Sigchain()
        event = _build_legacy_event(chain, sequence=1, prior_hash=GENESIS_HASH)
        assert event.sig_format_version is None

    def test_multiple_legacy_events_verify(self) -> None:
        chain = Sigchain()
        events: list[AuditEvent] = []
        prior = GENESIS_HASH
        for i in range(1, 4):
            e = _build_legacy_event(
                chain, sequence=i, prior_hash=prior, payload={"i": i}
            )
            prior = AuditEvent.hash_event_for_chain(e)
            events.append(e)
        assert chain.verify_chain(events) is True

    def test_tampered_legacy_payload_fails(self) -> None:
        chain = Sigchain()
        event = _build_legacy_event(chain, sequence=1, prior_hash=GENESIS_HASH, payload={"ok": True})
        tampered = dataclasses.replace(event, payload={"ok": False})
        assert chain.verify_chain([tampered]) is False


@needs_liboqs
class TestHybridSigFormatVersion:
    """Hybrid (Ed25519 + ML-DSA-65) entries after P2a."""

    def _hybrid_chain(self) -> Sigchain:
        from aevum.core.signing import DualSigner
        return Sigchain(dual_signer=DualSigner.generate())

    def test_key_scheme_is_hybrid(self) -> None:
        chain = self._hybrid_chain()
        e = chain.new_event(event_type="t", payload={}, actor="a")
        assert e.key_scheme == "ed25519+ml-dsa-65"

    def test_sig_format_version_is_1(self) -> None:
        chain = self._hybrid_chain()
        e = chain.new_event(event_type="t", payload={}, actor="a")
        assert e.sig_format_version == 1

    def test_round_trip_verifies(self) -> None:
        chain = self._hybrid_chain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert chain.verify_chain(events) is True

    def test_mutate_key_scheme_fails(self) -> None:
        """key_scheme is bound in signing_fields; mutation → canonical mismatch → False."""
        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        mutated = dataclasses.replace(event, key_scheme="ed25519")
        assert chain.verify_chain([mutated]) is False

    def test_remove_mldsa65_sig_fails(self) -> None:
        """Absence of mldsa65_sig on a hybrid entry is a tamper/downgrade → False."""
        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        stripped = dataclasses.replace(event, mldsa65_sig=None)
        assert chain.verify_chain([stripped]) is False

    def test_corrupt_mldsa65_sig_fails(self) -> None:
        """A corrupted ML-DSA signature must not verify."""
        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.mldsa65_sig is not None
        zeroed = "00" * (len(event.mldsa65_sig) // 2)
        mutated = dataclasses.replace(event, mldsa65_sig=zeroed)
        assert chain.verify_chain([mutated]) is False

    def test_strip_sig_format_version_fails(self) -> None:
        """Stripping sig_format_version → legacy path, 16-field signing_fields ≠ 18-field signed bytes → False."""
        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        stripped = dataclasses.replace(event, sig_format_version=None)
        assert chain.verify_chain([stripped]) is False

    def test_hybrid_without_liboqs_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verifying a hybrid entry when liboqs is absent must fail closed (not silently succeed)."""
        import aevum.core.signing as signing_mod

        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.key_scheme == "ed25519+ml-dsa-65"

        monkeypatch.setattr(signing_mod, "_OQS_AVAILABLE", False)
        assert chain.verify_chain([event]) is False
