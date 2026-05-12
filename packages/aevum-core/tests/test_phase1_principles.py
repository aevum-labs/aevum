# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

import pytest

from aevum.core.principles import Principles, PrinciplesError, PrinciplesVerifier


def make_test_principles_file(tmp_path: Path) -> tuple[Path, bytes]:
    """
    Create a valid signed_principles.yaml for testing using pyca/cryptography.
    Returns (path, private_key_bytes).
    """
    import base58
    import yaml
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    did_key = "did:key:z" + base58.b58encode(bytes([0xed, 0x01]) + pub_bytes).decode()

    content = {
        "format_version": "2.0",
        "schema": "aevum-principles-v2",
        "layers": {
            "immutable": {
                "principles": [
                    {"id": "life_first", "text": "Human wellbeing above all else."},
                    {"id": "crisis_barrier", "text": "Crisis barrier is absolute."},
                    {"id": "audit_trail", "text": "Everything is recorded."},
                    {"id": "govern_mandatory", "text": "Checkpoints are mandatory."},
                ]
            },
            "regulated": {
                "principles": [
                    {"id": "consent", "text": "Nothing without agreement."},
                ]
            },
            "operational": {
                "principles": [
                    {"id": "humility", "text": "Candidates not conclusions."},
                ]
            },
        }
    }

    content_bytes = json.dumps(
        content, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    sig_hex = private_key.sign(content_bytes).hex()

    envelope = {
        "format_version": "2.0",
        "sequence": 1,
        "signed_by": did_key,
        "content_sha256": content_hash,
        "signature_algorithm": "Ed25519",
        "signature": sig_hex,
        "signed_at": "2026-01-01T00:00:00+00:00",
        "previous_hash": None,
        "rekor_log_entry": None,
        "content": content,
    }

    sp_path = tmp_path / "signed_principles.yaml"
    with sp_path.open("w") as f:
        yaml.dump(envelope, f, default_flow_style=False)

    return sp_path, private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


class TestPrinciplesVerifier:
    def test_verify_valid_file_succeeds(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        verifier = PrinciplesVerifier(sp_path)
        result = verifier.verify()
        assert isinstance(result, Principles)

    def test_verify_returns_correct_sequence(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert result.sequence == 1

    def test_verify_returns_correct_layers(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert "immutable" in result.layers
        assert "regulated" in result.layers
        assert "operational" in result.layers

    def test_immutable_ids_contains_required(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        ids = result.immutable_ids()
        assert "life_first" in ids
        assert "crisis_barrier" in ids
        assert "audit_trail" in ids
        assert "govern_mandatory" in ids

    def test_regulated_ids(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert "consent" in result.regulated_ids()

    def test_operational_ids(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert "humility" in result.operational_ids()

    def test_missing_file_raises_principles_error(self, tmp_path):
        verifier = PrinciplesVerifier(tmp_path / "nonexistent.yaml")
        with pytest.raises(PrinciplesError, match="not found"):
            verifier.verify()

    def test_tampered_content_raises_principles_error(self, tmp_path):
        import yaml
        sp_path, _ = make_test_principles_file(tmp_path)
        with sp_path.open("r") as f:
            envelope = yaml.safe_load(f)
        # Tamper with the content
        envelope["content"]["format_version"] = "TAMPERED"
        with sp_path.open("w") as f:
            yaml.dump(envelope, f)
        with pytest.raises(PrinciplesError):
            PrinciplesVerifier(sp_path).verify()

    def test_wrong_signature_raises_principles_error(self, tmp_path):
        import yaml
        sp_path, _ = make_test_principles_file(tmp_path)
        with sp_path.open("r") as f:
            envelope = yaml.safe_load(f)
        # Corrupt the signature
        envelope["signature"] = "00" * 64
        with sp_path.open("w") as f:
            yaml.dump(envelope, f)
        with pytest.raises(PrinciplesError):
            PrinciplesVerifier(sp_path).verify()

    def test_missing_required_immutable_raises(self, tmp_path):
        import base58
        import yaml
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        # Content missing 'govern_mandatory'
        private_key = Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        did_key = "did:key:z" + base58.b58encode(
            bytes([0xed, 0x01]) + pub_bytes
        ).decode()
        content = {
            "layers": {
                "immutable": {
                    "principles": [
                        {"id": "life_first", "text": "..."},
                        # missing crisis_barrier, audit_trail, govern_mandatory
                    ]
                }
            }
        }
        content_bytes = json.dumps(
            content, sort_keys=True, separators=(",", ":")
        ).encode()
        envelope = {
            "signed_by": did_key,
            "content_sha256": hashlib.sha256(content_bytes).hexdigest(),
            "signature": private_key.sign(content_bytes).hex(),
            "content": content,
        }
        sp_path = tmp_path / "signed_principles.yaml"
        with sp_path.open("w") as f:
            yaml.dump(envelope, f)
        with pytest.raises(PrinciplesError, match="missing"):
            PrinciplesVerifier(sp_path).verify()

    def test_invalid_yaml_raises_principles_error(self, tmp_path):
        sp_path = tmp_path / "signed_principles.yaml"
        sp_path.write_text("this: is: not: valid: yaml: ::::")
        with pytest.raises(PrinciplesError):
            PrinciplesVerifier(sp_path).verify()

    def test_not_a_mapping_raises_principles_error(self, tmp_path):
        sp_path = tmp_path / "signed_principles.yaml"
        sp_path.write_text("- item1\n- item2\n")
        with pytest.raises(PrinciplesError):
            PrinciplesVerifier(sp_path).verify()

    def test_missing_signed_by_raises(self, tmp_path):
        import yaml
        sp_path, _ = make_test_principles_file(tmp_path)
        with sp_path.open("r") as f:
            envelope = yaml.safe_load(f)
        del envelope["signed_by"]
        with sp_path.open("w") as f:
            yaml.dump(envelope, f)
        with pytest.raises(PrinciplesError):
            PrinciplesVerifier(sp_path).verify()

    def test_format_version_in_result(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert result.format_version == "2.0"

    def test_signed_at_in_result(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert result.signed_at == "2026-01-01T00:00:00+00:00"

    def test_signed_by_is_did_key(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        result = PrinciplesVerifier(sp_path).verify()
        assert result.signed_by.startswith("did:key:z")
