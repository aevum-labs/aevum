# SPDX-License-Identifier: Apache-2.0
"""P1 fail-closed assertions — run regardless of whether liboqs is installed.

These tests validate that DualSigner.generate() and DualSigner.load() raise
SignerUnavailableError (not a warning, not a degraded object) when liboqs is
absent or when PQC key files are missing.  They use monkeypatching, so the
liboqs C library is not required to execute them.
"""
import pathlib

import pytest
from unittest.mock import patch

import nacl.signing

from aevum.core.signing import DualSigner, SignerUnavailableError


class TestFailClosedGenerate:
    def test_generate_raises_signer_unavailable_when_liboqs_absent(self):
        with patch("aevum.core.signing._OQS_AVAILABLE", False):
            with pytest.raises(SignerUnavailableError) as exc_info:
                DualSigner.generate()
        msg = str(exc_info.value)
        assert "aevum-core[pqc]" in msg, "error must name the install target"
        assert "ADR-012" in msg, "error must reference ADR-012 for classical-only opt-in"

    def test_generate_does_not_return_ed25519_only_signer_when_liboqs_absent(self):
        with patch("aevum.core.signing._OQS_AVAILABLE", False):
            with pytest.raises(SignerUnavailableError):
                DualSigner.generate()
        # If we reach here without exception that would be the bug — pytest.raises handles it.

    def test_generate_raises_not_warns_when_liboqs_absent(self, recwarn):
        with patch("aevum.core.signing._OQS_AVAILABLE", False):
            with pytest.raises(SignerUnavailableError):
                DualSigner.generate()
        assert len(recwarn) == 0, "must raise, not warn"


class TestFailClosedLoad:
    def test_load_raises_signer_unavailable_when_mldsa65_files_absent(self, tmp_path):
        # Write only the Ed25519 key (simulates pre-P1 keys directory)
        ed25519_sk = nacl.signing.SigningKey.generate()
        key_path = tmp_path / "ed25519.key"
        key_path.write_bytes(bytes(ed25519_sk))
        key_path.chmod(0o600)

        with pytest.raises(SignerUnavailableError) as exc_info:
            DualSigner.load(tmp_path)
        msg = str(exc_info.value)
        assert "aevum-core[pqc]" in msg, "error must name the install target"
        assert "ADR-012" in msg, "error must reference ADR-012"

    def test_load_raises_when_only_sk_present(self, tmp_path):
        ed25519_sk = nacl.signing.SigningKey.generate()
        (tmp_path / "ed25519.key").write_bytes(bytes(ed25519_sk))
        (tmp_path / "mldsa65.sk").write_bytes(b"fake_sk")
        # mldsa65.pk is absent

        with pytest.raises(SignerUnavailableError):
            DualSigner.load(tmp_path)

    def test_load_raises_when_only_pk_present(self, tmp_path):
        ed25519_sk = nacl.signing.SigningKey.generate()
        (tmp_path / "ed25519.key").write_bytes(bytes(ed25519_sk))
        (tmp_path / "mldsa65.pk").write_bytes(b"fake_pk")
        # mldsa65.sk is absent

        with pytest.raises(SignerUnavailableError):
            DualSigner.load(tmp_path)


class TestSignerUnavailableErrorCatchability:
    def test_signer_unavailable_error_is_exception(self):
        assert issubclass(SignerUnavailableError, Exception)

    def test_signer_unavailable_error_is_not_import_error(self):
        assert not issubclass(SignerUnavailableError, ImportError), (
            "SignerUnavailableError must be its own type so P2 opt-in can branch on it cleanly"
        )
