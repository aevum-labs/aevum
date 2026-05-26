# SPDX-License-Identifier: Apache-2.0
import stat

import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, RuntimeError, SystemExit):
    pytest.skip("liboqs native library not available — skipping oqs-dependent tests", allow_module_level=True)

from aevum.core.signing import DualSignature, DualSigner, SignatureError


class TestDualSignerGenerate:
    def test_generate_returns_dual_signer(self):
        signer = DualSigner.generate()
        assert isinstance(signer, DualSigner)

    def test_ed25519_public_key_is_32_bytes(self):
        signer = DualSigner.generate()
        assert len(signer.ed25519_public_key) == 32

    def test_mldsa65_public_key_is_1952_bytes(self):
        signer = DualSigner.generate()
        assert len(signer.mldsa65_public_key) == 1952

    def test_two_generates_produce_different_keys(self):
        s1 = DualSigner.generate()
        s2 = DualSigner.generate()
        assert s1.ed25519_public_key != s2.ed25519_public_key
        assert s1.mldsa65_public_key != s2.mldsa65_public_key


class TestDualSignerSaveLoad:
    def test_save_creates_key_files(self, tmp_path):
        signer = DualSigner.generate()
        signer.save(tmp_path)
        assert (tmp_path / "ed25519.key").exists()
        assert (tmp_path / "mldsa65.sk").exists()
        assert (tmp_path / "mldsa65.pk").exists()

    def test_load_after_save_roundtrip(self, tmp_path):
        signer = DualSigner.generate()
        signer.save(tmp_path)
        loaded = DualSigner.load(tmp_path)
        assert signer.ed25519_public_key == loaded.ed25519_public_key
        assert signer.mldsa65_public_key == loaded.mldsa65_public_key

    def test_loaded_signer_produces_same_signatures(self, tmp_path):
        signer = DualSigner.generate()
        signer.save(tmp_path)
        loaded = DualSigner.load(tmp_path)
        data = b"test payload"
        sig1 = signer.sign(data)
        sig2 = loaded.sign(data)
        # Same key, different nonce in ML-DSA — sigs differ but both verify
        DualSigner.verify(data, sig1)
        DualSigner.verify(data, sig2)

    def test_load_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            DualSigner.load(tmp_path / "nonexistent")

    def test_key_files_have_restrictive_permissions(self, tmp_path):
        signer = DualSigner.generate()
        signer.save(tmp_path)
        mode = (tmp_path / "ed25519.key").stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
        mode_sk = (tmp_path / "mldsa65.sk").stat().st_mode
        assert stat.S_IMODE(mode_sk) == 0o600


class TestDualSignerSign:
    def test_sign_returns_dual_signature(self):
        signer = DualSigner.generate()
        result = signer.sign(b"data")
        assert isinstance(result, DualSignature)

    def test_ed25519_sig_is_64_bytes(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"data")
        assert len(sig.ed25519_sig) == 64

    def test_mldsa65_sig_is_3309_bytes(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"data")
        assert len(sig.mldsa65_sig) == 3309

    def test_ed25519_pub_in_signature_matches_signer(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"data")
        assert sig.ed25519_pub == signer.ed25519_public_key

    def test_mldsa65_pub_in_signature_matches_signer(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"data")
        assert sig.mldsa65_pub == signer.mldsa65_public_key

    def test_empty_payload_signs_successfully(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"")
        assert len(sig.ed25519_sig) == 64
        assert len(sig.mldsa65_sig) == 3309

    def test_large_payload_signs_successfully(self):
        signer = DualSigner.generate()
        data = b"x" * 1_000_000
        sig = signer.sign(data)
        DualSigner.verify(data, sig)


class TestDualSignerVerify:
    def test_verify_valid_signature_succeeds(self):
        signer = DualSigner.generate()
        data = b"verify me"
        sig = signer.sign(data)
        DualSigner.verify(data, sig)  # must not raise

    def test_verify_tampered_data_raises_signature_error(self):
        signer = DualSigner.generate()
        data = b"original"
        sig = signer.sign(data)
        with pytest.raises(SignatureError):
            DualSigner.verify(b"tampered", sig)

    def test_verify_wrong_ed25519_sig_raises(self):
        signer = DualSigner.generate()
        data = b"data"
        sig = signer.sign(data)
        bad_sig = DualSignature(
            ed25519_sig=bytes(64),  # all-zero invalid sig
            mldsa65_sig=sig.mldsa65_sig,
            ed25519_pub=sig.ed25519_pub,
            mldsa65_pub=sig.mldsa65_pub,
        )
        with pytest.raises(SignatureError):
            DualSigner.verify(data, bad_sig)

    def test_verify_wrong_mldsa65_sig_raises(self):
        signer = DualSigner.generate()
        data = b"data"
        sig = signer.sign(data)
        bad_sig = DualSignature(
            ed25519_sig=sig.ed25519_sig,
            mldsa65_sig=bytes(3309),  # all-zero invalid sig
            ed25519_pub=sig.ed25519_pub,
            mldsa65_pub=sig.mldsa65_pub,
        )
        with pytest.raises(SignatureError):
            DualSigner.verify(data, bad_sig)

    def test_verify_cross_signer_ed25519_raises(self):
        """Sig from signer1 should not verify with signer2's pubkey."""
        s1 = DualSigner.generate()
        s2 = DualSigner.generate()
        data = b"data"
        sig1 = s1.sign(data)
        # Replace ed25519_pub with s2's pubkey
        bad_sig = DualSignature(
            ed25519_sig=sig1.ed25519_sig,
            mldsa65_sig=sig1.mldsa65_sig,
            ed25519_pub=s2.ed25519_public_key,
            mldsa65_pub=sig1.mldsa65_pub,
        )
        with pytest.raises(SignatureError):
            DualSigner.verify(data, bad_sig)


class TestDualSignatureSerialization:
    def test_to_dict_and_from_dict_roundtrip(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"serialize me")
        d = sig.to_dict()
        assert all(isinstance(v, str) for v in d.values())
        restored = DualSignature.from_dict(d)
        assert restored == sig

    def test_to_dict_values_are_hex_strings(self):
        signer = DualSigner.generate()
        sig = signer.sign(b"hex")
        d = sig.to_dict()
        # All values parseable as hex
        for key, val in d.items():
            bytes.fromhex(val), f"{key} is not valid hex"

    def test_from_dict_produces_verifiable_signature(self):
        signer = DualSigner.generate()
        data = b"roundtrip"
        sig = signer.sign(data)
        restored = DualSignature.from_dict(sig.to_dict())
        DualSigner.verify(data, restored)  # must not raise
