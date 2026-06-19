# SPDX-License-Identifier: Apache-2.0
"""Robustness and DoS-guard tests for aevum-verify.

Exercises hostile/malformed input: corrupt JSON, truncated files, missing
required fields, wrong-length keys, garbage-hex embedded fields, and
oversized hex/array inputs. Every case must fail closed (FAILED / False /
a caught exception at the CLI boundary) — never an unhandled traceback and
never quietly accepted as valid.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest
from aevum.core.audit.sigchain import Sigchain
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aevum.verify._core import MAX_CHAIN_ENTRIES, VerifyEvent, dump_chain, load_chain, verify_entry, verify_sth
from aevum.verify._format import MAX_HEX_FIELD_LEN, hash_payload, message_representative, safe_fromhex


def _classical_chain_file(tmp_path: Path, n: int = 2) -> tuple[Sigchain, Path]:
    chain = Sigchain()
    events = [chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="test-suite") for i in range(n)]
    path = tmp_path / "chain.json"
    dump_chain(events, path)
    return chain, path


def _signed_hybrid_shaped_entry() -> tuple[VerifyEvent, bytes]:
    """A real Ed25519-signed entry whose key_scheme claims hybrid, for bug #1 (garbage mldsa65_pub).

    mldsa65_pub/mldsa65_sig are not part of the signed field set (spec "Hash
    Chain"), so they can be replaced with garbage without invalidating the
    Ed25519 signature — letting this test exercise the embedded-pubkey check
    without needing liboqs.
    """
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload_hash = hash_payload({})
    signing_fields = {
        "event_id": "e1", "episode_id": "ep1", "sequence": 1, "event_type": "t",
        "schema_version": "1", "valid_from": "2026-01-01T00:00:00Z", "valid_to": None,
        "system_time": "1", "causation_id": None, "correlation_id": None, "actor": "a",
        "trace_id": None, "span_id": None, "payload_hash": payload_hash, "prior_hash": "0" * 64,
        "signer_key_id": "k1", "key_scheme": "ed25519+ml-dsa-65", "sig_format_version": 1,
        "hash_alg": "sha3-256",
    }
    digest = hashlib.sha3_256(message_representative(signing_fields)).digest()
    sig_str = base64.urlsafe_b64encode(priv.sign(digest)).decode().rstrip("=")
    entry = VerifyEvent(
        event_id="e1", episode_id="ep1", sequence=1, event_type="t",
        schema_version="1", valid_from="2026-01-01T00:00:00Z", valid_to=None,
        system_time=1, causation_id=None, correlation_id=None, actor="a",
        trace_id=None, span_id=None, payload={}, payload_hash=payload_hash,
        prior_hash="0" * 64, signature=sig_str, signer_key_id="k1",
        mldsa65_sig="aa" * 100, mldsa65_pub="placeholder", key_scheme="ed25519+ml-dsa-65",
        sig_format_version=1,
    )
    return entry, pub_bytes


class TestMalformedInput:
    def test_malformed_json_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "chain.json"
        path.write_text("{not valid json at all")
        with pytest.raises(json.JSONDecodeError):
            load_chain(path)

    def test_malformed_json_cli_exits_2(self, tmp_path: Path) -> None:
        path = tmp_path / "chain.json"
        path.write_text("{not valid json at all")
        proc = subprocess.run(
            [sys.executable, "-m", "aevum.verify", str(path), "--ed25519-pub", "00" * 32],
            capture_output=True, text=True,
        )
        assert proc.returncode == 2, f"expected exit 2; got {proc.returncode}, stderr={proc.stderr}"

    def test_truncated_chain_file_fails_closed(self, tmp_path: Path) -> None:
        chain, path = _classical_chain_file(tmp_path, n=2)
        raw = path.read_text()
        path.write_text(raw[: len(raw) // 2])  # chop the file mid-entry
        with pytest.raises(json.JSONDecodeError):
            load_chain(path)

    def test_truncated_chain_file_cli_exits_2(self, tmp_path: Path) -> None:
        chain, path = _classical_chain_file(tmp_path, n=2)
        raw = path.read_text()
        path.write_text(raw[: len(raw) // 2])
        proc = subprocess.run(
            [
                sys.executable, "-m", "aevum.verify", str(path),
                "--ed25519-pub", chain._signer.public_key_bytes().hex(),
            ],
            capture_output=True, text=True,
        )
        assert proc.returncode == 2, f"expected exit 2; got {proc.returncode}, stderr={proc.stderr}"

    def test_missing_required_key_fails_closed(self, tmp_path: Path) -> None:
        chain, path = _classical_chain_file(tmp_path, n=1)
        entries = json.loads(path.read_text())
        del entries[0]["event_id"]
        path.write_text(json.dumps(entries))
        with pytest.raises(KeyError):
            load_chain(path)

    def test_missing_required_key_cli_exits_2(self, tmp_path: Path) -> None:
        chain, path = _classical_chain_file(tmp_path, n=1)
        entries = json.loads(path.read_text())
        del entries[0]["event_id"]
        path.write_text(json.dumps(entries))
        proc = subprocess.run(
            [
                sys.executable, "-m", "aevum.verify", str(path),
                "--ed25519-pub", chain._signer.public_key_bytes().hex(),
            ],
            capture_output=True, text=True,
        )
        assert proc.returncode == 2, f"expected exit 2; got {proc.returncode}, stderr={proc.stderr}"

    def test_wrong_length_ed25519_key_fails_closed_not_crash(self, tmp_path: Path) -> None:
        """A 16-byte (not 32-byte) Ed25519 key must produce FAILED, never a traceback."""
        chain, path = _classical_chain_file(tmp_path, n=1)
        proc = subprocess.run(
            [sys.executable, "-m", "aevum.verify", str(path), "--ed25519-pub", "00" * 16],
            capture_output=True, text=True,
        )
        assert proc.returncode == 1, f"expected exit 1 (FAILED); got {proc.returncode}, stderr={proc.stderr}"
        assert "Traceback" not in proc.stderr


class TestEmbeddedGarbageHex:
    def test_garbage_hex_mldsa65_pub_fails_closed_not_raise(self) -> None:
        """Bug #1: malformed mldsa65_pub hex must return FAILED, never raise."""
        entry, pub_bytes = _signed_hybrid_shaped_entry()
        result = verify_entry(
            entry, ed25519_pub=pub_bytes, mldsa65_pub=b"\x00" * 1952, expected_prior="0" * 64,
        )
        assert result.ok is False
        assert "mldsa65_pub" in result.reason

    def test_garbage_hex_root_hash_fails_closed_not_raise(self) -> None:
        """Bug #2: malformed STH root_hash hex must return False, never raise."""
        sth = types.SimpleNamespace(
            tree_size=1, root_hash="not-valid-hex-ZZZ", timestamp=0, log_id="aa" * 32,
            hash_alg="sha3-256", key_scheme="ed25519+ml-dsa-65", ed25519_sig="AA==",
            mldsa65_sig="00" * 32, mldsa65_pub="00" * 32, ed25519_pub="00" * 32, tsa_token=None,
        )
        assert verify_sth(sth, ed25519_pub=b"\x00" * 32, mldsa65_pub=b"\x00" * 32, expected_root=b"\x01" * 32) is False


class TestDosGuards:
    def test_safe_fromhex_rejects_oversized_input(self) -> None:
        oversized = "a" * (MAX_HEX_FIELD_LEN + 1)
        with pytest.raises(ValueError):
            safe_fromhex(oversized)

    def test_oversized_embedded_hex_field_rejected_not_processed(self) -> None:
        """An oversized hostile mldsa65_pub must be rejected by the length guard, not bytes.fromhex'd in full."""
        entry, pub_bytes = _signed_hybrid_shaped_entry()
        entry = VerifyEvent(**{**entry.__dict__, "mldsa65_pub": "a" * (MAX_HEX_FIELD_LEN + 1)})
        result = verify_entry(
            entry, ed25519_pub=pub_bytes, mldsa65_pub=b"\x00" * 1952, expected_prior="0" * 64,
        )
        assert result.ok is False
        assert "exceeds" in result.reason

    def test_oversized_chain_entry_count_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "huge.json"
        path.write_text(json.dumps([{} for _ in range(MAX_CHAIN_ENTRIES + 1)]))
        with pytest.raises(ValueError, match="exceeds"):
            load_chain(path)
