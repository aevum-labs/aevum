# SPDX-License-Identifier: Apache-2.0
"""P2b-2 gate tests: ML-DSA-only hybrid verification; redundant ed25519_sig dropped.

Verifies:
  1. New hybrid entries have ed25519_sig=None, mldsa65_sig is not None; verify_chain True.
  2. Downgrade still caught: strip mldsa65_sig → False; tamper mldsa65_sig → False;
     flip key_scheme → False (P2a binding intact).
  3. Classical entry (key_scheme==ed25519) → True; primary Ed25519 still the proof.
"""
from __future__ import annotations

import dataclasses

import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, SystemExit):
    pytest.skip(
        "liboqs native library not available — skipping P2b-2 ML-DSA-only hybrid tests",
        allow_module_level=True,
    )

from test_phase1_principles import make_test_principles_file


def _boot_kernel(tmp_path, sp_path):
    from aevum.core.kernel import Kernel
    return Kernel.local(
        state_dir=tmp_path / "state",
        principles_path=sp_path,
        tsa_enabled=False,
    )


class TestNewHybridEntryDropsEd25519Sig:
    def test_ed25519_sig_is_none_on_new_hybrid_entry(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.hybrid",
            payload={"test": "p2b2"},
            actor="test-suite",
        )

        assert event.key_scheme == "ed25519+ml-dsa-65"
        assert not hasattr(event, "ed25519_sig") or event.ed25519_sig is None, \
            "ed25519_sig must not be present on AuditEvent (removed in P2f)"
        assert event.mldsa65_sig is not None, "mldsa65_sig must be populated"
        assert event.mldsa65_pub is not None, "mldsa65_pub must be populated"

    def test_verify_chain_true_for_new_hybrid_entry(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        events = [
            kernel.sigchain.new_event(
                event_type=f"p2b2.verify.{i}",
                payload={"i": i},
                actor="test-suite",
            )
            for i in range(3)
        ]

        assert kernel.sigchain.verify_chain(events) is True


class TestDowngradeDefenses:
    def test_strip_mldsa65_sig_returns_false(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.downgrade.strip",
            payload={"probe": "strip"},
            actor="test-suite",
        )
        tampered = dataclasses.replace(event, mldsa65_sig=None)

        assert kernel.sigchain.verify_chain([tampered]) is False

    def test_tamper_mldsa65_sig_returns_false(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.downgrade.tamper",
            payload={"probe": "tamper"},
            actor="test-suite",
        )
        # Flip the last byte of the ML-DSA-65 signature
        bad_sig = bytes.fromhex(event.mldsa65_sig)
        bad_sig = bad_sig[:-1] + bytes([bad_sig[-1] ^ 0xFF])
        tampered = dataclasses.replace(event, mldsa65_sig=bad_sig.hex())

        assert kernel.sigchain.verify_chain([tampered]) is False

    def test_flip_key_scheme_returns_false(self, tmp_path):
        """P2a binding: changing key_scheme from hybrid to classical must fail (signed field)."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.downgrade.scheme",
            payload={"probe": "scheme"},
            actor="test-suite",
        )
        # Flip from hybrid to classical — invalidates the primary Ed25519 signature
        tampered = dataclasses.replace(event, key_scheme="ed25519")

        assert kernel.sigchain.verify_chain([tampered]) is False


class TestBackCompat:
    def test_classical_entry_key_scheme_ed25519_verifies(self, tmp_path):
        """Classical entry with key_scheme==ed25519 and no dual fields must verify True."""
        from aevum.core.audit.sigchain import Sigchain

        chain = Sigchain()  # no dual_signer → classical-only entries
        events = [
            chain.new_event(event_type=f"p2b2.classical.{i}", payload={"i": i}, actor="test-suite")
            for i in range(3)
        ]

        assert all(e.key_scheme == "ed25519" for e in events)
        assert all(e.mldsa65_sig is None for e in events)
        assert chain.verify_chain(events) is True
