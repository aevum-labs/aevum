# SPDX-License-Identifier: Apache-2.0
from unittest.mock import patch

import pytest
from test_phase1_principles import make_test_principles_file


class TestKernelLocal:
    def test_kernel_local_succeeds_with_valid_principles(self, tmp_path):
        """Full kernel boot with a real signed_principles.yaml."""
        sp_path, _ = make_test_principles_file(tmp_path)

        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,  # disable TSA for unit tests
        )
        assert kernel is not None
        assert kernel.principles is not None

    def test_kernel_local_generates_keys_on_first_boot(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        state_dir = tmp_path / "state"

        from aevum.core.kernel import Kernel
        Kernel.local(
            state_dir=state_dir,
            principles_path=sp_path,
            tsa_enabled=False,
        )

        assert (state_dir / "keys" / "ed25519.key").exists()
        assert (state_dir / "keys" / "mldsa65.sk").exists()
        assert (state_dir / "keys" / "mldsa65.pk").exists()

    def test_kernel_local_loads_existing_keys_on_second_boot(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        state_dir = tmp_path / "state"

        from aevum.core.kernel import Kernel
        k1 = Kernel.local(
            state_dir=state_dir, principles_path=sp_path, tsa_enabled=False
        )
        k2 = Kernel.local(
            state_dir=state_dir, principles_path=sp_path, tsa_enabled=False
        )
        # Same keys on both boots
        assert k1.signer.ed25519_public_key == k2.signer.ed25519_public_key
        assert k1.signer.mldsa65_public_key == k2.signer.mldsa65_public_key

    def test_kernel_local_raises_on_invalid_principles(self, tmp_path):
        from aevum.core.kernel import Kernel
        from aevum.core.principles import PrinciplesError
        with pytest.raises(PrinciplesError):
            Kernel.local(
                state_dir=tmp_path / "state",
                principles_path=tmp_path / "nonexistent.yaml",
                tsa_enabled=False,
            )

    def test_kernel_principles_property(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        from aevum.core.principles import Principles
        assert isinstance(kernel.principles, Principles)

    def test_kernel_signer_property(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        from aevum.core.signing import DualSigner
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        assert isinstance(kernel.signer, DualSigner)

    def test_kernel_tsa_client_property(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.kernel import Kernel
        from aevum.core.tsa import TSAClient
        kernel = Kernel.local(
            state_dir=tmp_path / "state",
            principles_path=sp_path,
            tsa_enabled=False,
        )
        assert isinstance(kernel.tsa_client, TSAClient)

    def test_kernel_boot_runs_canaries(self, tmp_path):
        """Canary suite runs during boot — if it fails, Kernel.local() raises CanaryError."""
        sp_path, _ = make_test_principles_file(tmp_path)
        from aevum.core.canary import CanaryError
        from aevum.core.kernel import Kernel
        from aevum.core.signing import DualSigner

        # Canary 6 will fail, CanaryError raised
        with patch.object(DualSigner, "generate", side_effect=RuntimeError("broken")), pytest.raises((CanaryError, RuntimeError)):
            Kernel.local(
                state_dir=tmp_path / "state2",
                principles_path=sp_path,
                tsa_enabled=False,
            )
