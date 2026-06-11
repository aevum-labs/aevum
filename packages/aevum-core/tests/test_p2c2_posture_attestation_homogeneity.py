# SPDX-License-Identifier: Apache-2.0
"""P2c-2 gate tests: signed posture attestation + verify_chain homogeneity enforcement.

Two decoupled properties:
  (A) Attestation: classical-only Engine writes a signed posture.attestation as entry #1;
      hybrid + bare-default Engines write NO attestation (session.start stays entry #1).
  (B) Homogeneity: verify_chain rejects any fmt==1 chain that mixes ed25519 and
      ed25519+ml-dsa-65 entries (downgrade/splice defence). fmt==None legacy entries exempt.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from test_p2a_sig_format_versioning import _build_legacy_event
from test_phase1_principles import make_test_principles_file

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import GENESIS_HASH, Sigchain

try:
    import oqs as _oqs_check  # noqa: F401
    _LIBOQS_PRESENT = True
except (ImportError, OSError, SystemExit):
    _LIBOQS_PRESENT = False

needs_liboqs = pytest.mark.skipif(not _LIBOQS_PRESENT, reason="liboqs not available")


def _no_liboqs():
    return patch.multiple(
        "aevum.core.signing",
        _OQS_AVAILABLE=False,
        _oqs_module=None,
    )


def _boot_classical(tmp_path, sp_path):
    from aevum.core.kernel import Kernel
    return Kernel.local(
        state_dir=tmp_path / "state",
        principles_path=sp_path,
        tsa_enabled=False,
        posture="classical-only",
    )


# ── (A) Attestation ──────────────────────────────────────────────────────────

class TestPostureAttestationClassicalOnly:
    """classical-only Engine writes posture.attestation as chain entry #1."""

    def test_attestation_is_first_entry(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        assert events[0].event_type == "posture.attestation"

    def test_attestation_payload(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        p = events[0].payload
        assert p["signing_posture"] == "classical-only"
        assert p["scheme"] == "ed25519"
        assert p["post_quantum"] is False

    def test_attestation_entry_is_ed25519(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        assert events[0].key_scheme == "ed25519"
        assert events[0].sig_format_version == 1

    def test_session_start_is_second_entry(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        assert len(events) == 2
        assert events[1].event_type == "session.start"

    def test_attestation_is_signed_verify_chain_true(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        assert engine.verify_sigchain() is True  # type: ignore[attr-defined]

    def test_attestation_actor_is_aevum_core(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        assert events[0].actor == "aevum-core"


@needs_liboqs
class TestNoAttestationHybrid:
    """hybrid kernel engine writes NO posture.attestation; session.start stays entry #1."""

    def test_no_attestation_in_hybrid_chain(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        assert not any(e.event_type == "posture.attestation" for e in events)

    def test_session_start_is_first_entry_hybrid(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        engine = kernel.engine()
        events = engine._ledger.all_events()  # type: ignore[attr-defined]
        assert events[0].event_type == "session.start"

    def test_hybrid_engine_verify_chain_true(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        engine = kernel.engine()
        assert engine.verify_sigchain() is True  # type: ignore[attr-defined]


class TestNoAttestationBareEngine:
    """Bare Engine() writes NO posture.attestation; session.start stays entry #1."""

    def test_no_attestation_in_bare_engine(self):
        from aevum.core.engine import Engine
        engine = Engine()
        events = engine._ledger.all_events()
        assert not any(e.event_type == "posture.attestation" for e in events)

    def test_session_start_is_first_entry_bare(self):
        from aevum.core.engine import Engine
        engine = Engine()
        entries = engine.get_ledger_entries()
        assert entries[0]["event_type"] == "session.start"

    def test_bare_engine_len_1_session_start_only(self):
        """Mirrors test_functions.py:304 — bare Engine() entry #0 is session.start."""
        from aevum.core.engine import Engine
        engine = Engine()
        assert engine.ledger_count() == 1

    def test_bare_engine_commit_gives_len_2(self):
        """Mirrors test_functions.py:35 — bare Engine() + 1 commit = 2 entries."""
        from aevum.core.engine import Engine
        engine = Engine()
        engine.commit(event_type="app.t", payload={}, actor="a", idempotency_key="k1")
        assert engine.ledger_count() == 2


# ── (B) Homogeneity enforcement ───────────────────────────────────────────────

class TestHomogeneityEnforcement:
    """verify_chain rejects mixed-scheme fmt==1 chains; passes homogeneous and legacy chains."""

    def test_mixed_scheme_chain_rejected(self):
        """Chain mixing ed25519 and ed25519+ml-dsa-65 fmt==1 entries → False."""
        if not _LIBOQS_PRESENT:
            pytest.skip("liboqs required to produce hybrid events")

        from aevum.core.signing import DualSigner

        classical_chain = Sigchain()
        e1 = classical_chain.new_event(event_type="t.classical", payload={}, actor="a")
        assert e1.key_scheme == "ed25519"
        assert e1.sig_format_version == 1

        hybrid_chain = Sigchain(dual_signer=DualSigner.generate())
        e2 = hybrid_chain.new_event(event_type="t.hybrid", payload={}, actor="a")
        assert e2.key_scheme == "ed25519+ml-dsa-65"
        assert e2.sig_format_version == 1

        # Mix fmt==1 entries with different schemes — homogeneity pre-pass fires first
        assert classical_chain.verify_chain([e1, e2]) is False

    def test_all_classical_chain_passes(self):
        """All-ed25519 fmt==1 chain → True."""
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert all(e.key_scheme == "ed25519" for e in events)
        assert chain.verify_chain(events) is True

    @needs_liboqs
    def test_all_hybrid_chain_passes(self):
        """All-ed25519+ml-dsa-65 fmt==1 chain → True."""
        from aevum.core.signing import DualSigner
        chain = Sigchain(dual_signer=DualSigner.generate())
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert all(e.key_scheme == "ed25519+ml-dsa-65" for e in events)
        assert chain.verify_chain(events) is True

    def test_legacy_fmt_none_chain_exempt_from_homogeneity(self):
        """fmt==None (pre-P2a legacy) entries carry no bound key_scheme → exempt; chain passes."""
        chain = Sigchain()
        events: list[AuditEvent] = []
        prior = GENESIS_HASH
        for i in range(1, 4):
            e = _build_legacy_event(chain, sequence=i, prior_hash=prior, payload={"i": i})
            prior = AuditEvent.hash_event_for_chain(e)
            events.append(e)
        assert all(e.sig_format_version is None for e in events)
        assert chain.verify_chain(events) is True

    def test_classical_engine_chain_homogeneity_passes(self, tmp_path):
        """Full classical-only Engine chain (attestation + session.start) is homogeneous → True."""
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            engine = kernel.engine()
        assert engine.verify_sigchain() is True  # type: ignore[attr-defined]
