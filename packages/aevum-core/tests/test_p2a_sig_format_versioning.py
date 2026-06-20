# SPDX-License-Identifier: Apache-2.0
"""P2a tests: sig_format_version binding and verify_chain rejection of unknown entries.

new_event() always produces sig_format_version 1 unless P2-IDENTITY-V2's
commitment_key_id is supplied (see test_identity_binding_v2.py for v2 coverage).
verify_chain accepts sig_format_version in {1, 2} (DD4, spec aevum-signing-v2.md)
and rejects any other value (None, 99, ...) immediately — no legacy fallback.
Mutating a v1 entry's declared sig_format_version to 2 is also rejected: 2 is a
known version, but the entry's signature was computed over the 19-field v1
signing set, not the 22-field v2 set verify_chain now expects for a v2-declared
entry — the digest mismatches and the Ed25519 check fails (DD3).
"""
from __future__ import annotations

import dataclasses

import pytest

from aevum.core.audit.sigchain import Sigchain

try:
    import oqs as _oqs_check  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


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

    def test_strip_sig_format_version_rejected(self) -> None:
        """sig_format_version=None is not 1 → rejected immediately by verify_chain."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        stripped = dataclasses.replace(event, sig_format_version=None)
        assert chain.verify_chain([stripped]) is False

    def test_sig_format_version_2_rejected(self) -> None:
        """2 is a known sig_format_version (DD4), but this entry's signature was
        computed over the v1 (19-field) signing set. Relabeling it as v2 makes
        verify_chain sign-check it against the v2 (22-field) set instead — the
        digest no longer matches and the Ed25519 check fails (DD3: no downgrade/
        relabel attack is possible without the private key)."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        future = dataclasses.replace(event, sig_format_version=2)
        assert chain.verify_chain([future]) is False

    def test_unknown_sig_format_version_fails(self) -> None:
        """Future format version (e.g. 99) must fail closed — this verifier cannot validate it."""
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        future = dataclasses.replace(event, sig_format_version=99)
        assert chain.verify_chain([future]) is False

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

    def test_strip_sig_format_version_rejected(self) -> None:
        """sig_format_version=None is not 1 → rejected immediately by verify_chain."""
        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        stripped = dataclasses.replace(event, sig_format_version=None)
        assert chain.verify_chain([stripped]) is False

    def test_sig_format_version_2_rejected(self) -> None:
        """2 is a known sig_format_version (DD4), but this entry's signature was
        computed over the v1 (19-field) signing set. Relabeling it as v2 makes
        verify_chain sign-check it against the v2 (22-field) set instead — the
        digest no longer matches and the Ed25519 check fails (DD3: no downgrade/
        relabel attack is possible without the private key)."""
        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        future = dataclasses.replace(event, sig_format_version=2)
        assert chain.verify_chain([future]) is False

    def test_hybrid_without_liboqs_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verifying a hybrid entry when liboqs is absent must fail closed (not silently succeed)."""
        import aevum.core.signing as signing_mod

        chain = self._hybrid_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.key_scheme == "ed25519+ml-dsa-65"

        monkeypatch.setattr(signing_mod, "_OQS_AVAILABLE", False)
        assert chain.verify_chain([event]) is False
