# SPDX-License-Identifier: Apache-2.0
"""P2c-1 gate tests: classical-only Ed25519 opt-in posture.

Verifies five properties:
  1. AEVUM_SIGNING_POSTURE=classical-only (or posture="classical-only") boots the kernel
     WITHOUT liboqs — does not fail closed.
  2. default/unset posture WITHOUT liboqs still fails closed (P1 invariant preserved).
  3. default + liboqs → hybrid unchanged (key_scheme="ed25519+ml-dsa-65").
  4. Classical entries have key_scheme="ed25519", mldsa65_sig=None, verify_chain=True.
  5. Classical identity persists across restart: same ed25519.key → same key_id → chain
     produced by "process A" verifies in "process B".
  6. Loud CLASSICAL-ONLY warning is emitted on classical-only boot.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from test_phase1_principles import make_test_principles_file

try:
    import oqs as _oqs_check  # noqa: F401
    _LIBOQS_PRESENT = True
except (ImportError, OSError, SystemExit):
    _LIBOQS_PRESENT = False

needs_liboqs = pytest.mark.skipif(not _LIBOQS_PRESENT, reason="liboqs not available")


def _no_liboqs():
    """Patch context manager: make signing module believe liboqs is absent."""
    return patch.multiple(
        "aevum.core.signing",
        _OQS_AVAILABLE=False,
        _oqs_module=None,
    )


def _boot_classical(tmp_path, sp_path, state_subdir="state", **kwargs):
    from aevum.core.kernel import Kernel
    return Kernel.local(
        state_dir=tmp_path / state_subdir,
        principles_path=sp_path,
        tsa_enabled=False,
        posture="classical-only",
        **kwargs,
    )


class TestClassicalOnlyBootsWithoutLiboqs:
    """Property 1 — classical-only boots even when liboqs is absent."""

    def test_classical_only_posture_param_boots(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
        assert kernel is not None

    def test_classical_only_env_var_boots(self, tmp_path, monkeypatch):
        sp_path, _ = make_test_principles_file(tmp_path)
        monkeypatch.setenv("AEVUM_SIGNING_POSTURE", "classical-only")
        with _no_liboqs():
            from aevum.core.kernel import Kernel
            kernel = Kernel.local(
                state_dir=tmp_path / "state",
                principles_path=sp_path,
                tsa_enabled=False,
            )
        assert kernel is not None

    def test_posture_param_overrides_env(self, tmp_path, monkeypatch):
        """posture= param overrides AEVUM_SIGNING_POSTURE env var."""
        sp_path, _ = make_test_principles_file(tmp_path)
        monkeypatch.setenv("AEVUM_SIGNING_POSTURE", "hybrid")
        with _no_liboqs():
            # param=classical-only wins even though env says hybrid
            kernel = _boot_classical(tmp_path, sp_path)
        assert kernel is not None


class TestDefaultFailsClosedWithoutLiboqs:
    """Property 2 — default/unset posture without liboqs still fails closed."""

    def test_default_posture_raises_without_liboqs(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.signing import SignerUnavailableError
        with _no_liboqs():
            from aevum.core.kernel import Kernel
            with pytest.raises(SignerUnavailableError):
                Kernel.local(
                    state_dir=tmp_path / "state",
                    principles_path=sp_path,
                    tsa_enabled=False,
                    # no posture → hybrid → liboqs absent → fail closed
                )

    def test_hybrid_explicit_raises_without_liboqs(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.signing import SignerUnavailableError
        with _no_liboqs():
            from aevum.core.kernel import Kernel
            with pytest.raises(SignerUnavailableError):
                Kernel.local(
                    state_dir=tmp_path / "state",
                    principles_path=sp_path,
                    tsa_enabled=False,
                    posture="hybrid",
                )


@needs_liboqs
class TestHybridUnchangedWithLiboqs:
    """Property 3 — default + liboqs → hybrid (key_scheme=ed25519+ml-dsa-65)."""

    def test_default_posture_is_hybrid(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        from aevum.core.signing import DualSigner
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        assert isinstance(kernel.signer, DualSigner)

    def test_hybrid_entry_key_scheme(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        event = kernel.sigchain.new_event(
            event_type="test.hybrid", payload={"posture": "hybrid"}, actor="test"
        )
        assert event.key_scheme == "ed25519+ml-dsa-65"
        assert event.mldsa65_sig is not None


class TestClassicalEntries:
    """Property 4 — classical entries: key_scheme="ed25519", mldsa65_sig=None, verify_chain=True."""

    def test_entry_key_scheme_is_ed25519(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            event = kernel.sigchain.new_event(
                event_type="test.classical", payload={"mode": "classical"}, actor="test"
            )
        assert event.key_scheme == "ed25519"

    def test_entry_mldsa65_sig_is_none(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            event = kernel.sigchain.new_event(
                event_type="test.no_mldsa", payload={}, actor="test"
            )
        assert event.mldsa65_sig is None

    def test_verify_chain_is_true(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
            events = [
                kernel.sigchain.new_event(
                    event_type=f"test.verify.{i}", payload={"i": i}, actor="test"
                )
                for i in range(3)
            ]
        assert kernel.sigchain.verify_chain(events) is True

    def test_signer_is_not_dual_signer(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.signing import DualSigner
        with _no_liboqs():
            kernel = _boot_classical(tmp_path, sp_path)
        assert not isinstance(kernel.signer, DualSigner)


class TestClassicalRestartStability:
    """Property 5 — classical identity persists across restart."""

    def test_same_key_id_across_restarts(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            k1 = _boot_classical(tmp_path, sp_path)
            k2 = _boot_classical(tmp_path, sp_path)
        assert k1.signer.key_id == k2.signer.key_id, (
            "key_id changed between classical-only boots — identity not persisted"
        )

    def test_chain_from_first_boot_verifies_in_second_boot(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            # Process A
            k_a = _boot_classical(tmp_path, sp_path)
            events_a = [
                k_a.sigchain.new_event(
                    event_type=f"test.restart.{i}",
                    payload={"boot": "A", "i": i},
                    actor="process-A",
                )
                for i in range(3)
            ]
            pub_a = k_a.signer.public_key_bytes()

            # Process B (same state_dir — simulates restart)
            k_b = _boot_classical(tmp_path, sp_path)
            pub_b = k_b.signer.public_key_bytes()

        assert pub_a == pub_b, "Ed25519 public key changed between boots"
        assert k_b.sigchain.verify_chain(events_a), (
            "Chain from process A must verify in process B — ephemeral-key defect present"
        )

    def test_ed25519_key_file_exists_after_boot(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            _boot_classical(tmp_path, sp_path)
        assert (tmp_path / "state" / "keys" / "ed25519.key").exists()

    def test_no_mldsa65_files_created(self, tmp_path):
        """Classical-only boot must not create liboqs key files."""
        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs():
            _boot_classical(tmp_path, sp_path)
        keys_dir = tmp_path / "state" / "keys"
        assert not (keys_dir / "mldsa65.sk").exists()
        assert not (keys_dir / "mldsa65.pk").exists()

    @needs_liboqs
    def test_shared_identity_with_hybrid_path(self, tmp_path):
        """If hybrid boot ran first, classical-only reuses the same ed25519.key."""
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel

        # First: hybrid boot (liboqs available)
        k_hybrid = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        hybrid_pub = k_hybrid.signer.ed25519_public_key

        # Second: classical-only boot from same state dir
        k_classical = _boot_classical(tmp_path, sp_path)
        classical_pub = k_classical.signer.public_key_bytes()

        assert hybrid_pub == classical_pub, (
            "Classical-only boot must reuse the same ed25519.key as the hybrid boot"
        )


class TestClassicalOnlyWarning:
    """Property 6 — loud CLASSICAL-ONLY warning is emitted on classical-only boot."""

    def test_warning_logged_on_classical_boot(self, tmp_path, caplog):
        import logging

        sp_path, _ = make_test_principles_file(tmp_path)
        with _no_liboqs(), caplog.at_level(logging.WARNING, logger="aevum.core.kernel"):
            _boot_classical(tmp_path, sp_path)

        assert "CLASSICAL-ONLY" in caplog.text, (
            "Expected CLASSICAL-ONLY warning in kernel log — not emitted"
        )
        assert "ML-DSA-65" in caplog.text, (
            "Warning must mention ML-DSA-65 so operators know what is missing"
        )

    def test_warning_not_logged_for_hybrid(self, tmp_path, caplog):
        """Hybrid boot must NOT emit the CLASSICAL-ONLY warning."""
        import logging

        sp_path, _ = make_test_principles_file(tmp_path)
        if not _LIBOQS_PRESENT:
            pytest.skip("liboqs required for hybrid boot test")

        from aevum.core.kernel import Kernel
        with caplog.at_level(logging.WARNING, logger="aevum.core.kernel"):
            Kernel.local(
                state_dir=tmp_path / "state",
                principles_path=sp_path,
                tsa_enabled=False,
            )

        assert "CLASSICAL-ONLY" not in caplog.text
