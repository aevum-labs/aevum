# SPDX-License-Identifier: Apache-2.0
"""P2j-2 gate tests: Merkle + STH signature + TSA cert-chain verification.

Test inventory:
  AST import test — _core.py never imports from aevum.core.audit.merkle
  Conformance cross-checks — verifier and aevum-core agree on inclusion/consistency
  recompute_root — matches aevum-core MerkleTree.root()
  verify_inclusion — valid proofs True; tamper / wrong index / index≥n False
  verify_consistency — valid proofs True; fork (modify-historical) False
  verify_sth (hybrid, WITH liboqs) — valid True; wrong key False; no mldsa65_pub False;
                                     STH root ≠ recomputed False
  verify_sth_tsa_full — valid token/root True; wrong root False; no token None;
                        tampered imprint False; wrong anchor cert False (mocked)
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Test data — fixed 32-byte digests for reproducibility
# ---------------------------------------------------------------------------
_D = [bytes([i] * 32) for i in range(20)]


# ---------------------------------------------------------------------------
# AST import test — Merkle independence
# ---------------------------------------------------------------------------

class TestMerkleIndependence:
    @staticmethod
    def _assert_no_aevum_core_import(source_path: Path) -> None:
        """Assert no import statement in source_path names aevum.core.* or
        aevum.publish.* — the two runtimes this module must never trust."""
        tree = ast.parse(source_path.read_text())
        forbidden_prefixes = ("aevum.core", "aevum.publish")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"{source_path.name}: import {alias.name} found — independence violated"
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith(forbidden_prefixes), (
                    f"{source_path.name}: from {module} import ... found — independence violated"
                )

    def test_ast_no_aevum_core_import_in_core(self) -> None:
        """AST-level check: no import statement in _core.py names any aevum.core module.

        Every algorithm in _core.py — entry/chain hashing, RFC 6962 Merkle
        verification, STH and TSA validation — is re-implemented from the public
        spec. None of it may import from the chain producer (any aevum.core.*
        module), so the verifier never trusts the producer's runtime.
        """
        import aevum.verify._core as _core_mod
        self._assert_no_aevum_core_import(Path(_core_mod.__file__))  # type: ignore[arg-type]

    def test_ast_no_aevum_core_import_in_format(self) -> None:
        """AST-level check: no import statement in _format.py names any aevum.core module.

        _format.py reimplements the signing-digest, payload-hash, and
        chain-hash primitives from the spec; it must not import them from the
        chain producer either.
        """
        import aevum.verify._format as _format_mod
        self._assert_no_aevum_core_import(Path(_format_mod.__file__))  # type: ignore[arg-type]

    def test_ast_no_aevum_publish_import_in_core(self) -> None:
        """AST-level check: no import statement in _core.py names any aevum.publish module.

        verify_receipt_tsa independently reimplements the CTT MessageImprint
        check for aevum.publish.encoder.ReceiptEncoder's COSE_Sign1 output. It
        must not import the encoder (or any other aevum.publish.* module), so
        the verifier never trusts the producer's runtime — same guarantee the
        two tests above already enforce for aevum.core.
        """
        import aevum.verify._core as _core_mod
        self._assert_no_aevum_core_import(Path(_core_mod.__file__))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Conformance cross-check helpers
# ---------------------------------------------------------------------------

def _core_tree(n: int) -> MerkleTree:  # type: ignore[name-defined]  # noqa: F821
    from aevum.core.audit.merkle import MerkleTree
    return MerkleTree(_D[:n])


def _core_lh(i: int) -> bytes:
    from aevum.core.audit.merkle import leaf_hash as core_leaf_hash
    return core_leaf_hash(_D[i])


# ---------------------------------------------------------------------------
# Conformance: recompute_root / leaf_hash / node_hash agree with aevum-core
# ---------------------------------------------------------------------------

class TestMerklePrimitivesConformance:
    def test_leaf_hash_matches_core(self) -> None:
        from aevum.core.audit.merkle import leaf_hash as core_lh

        from aevum.verify._core import leaf_hash as v_lh
        for i in range(10):
            assert v_lh(_D[i]) == core_lh(_D[i]), f"leaf_hash mismatch at i={i}"

    def test_node_hash_matches_core(self) -> None:
        from aevum.core.audit.merkle import node_hash as core_nh

        from aevum.verify._core import leaf_hash
        from aevum.verify._core import node_hash as v_nh
        for i in range(5):
            left = leaf_hash(_D[i])
            right = leaf_hash(_D[i + 1])
            assert v_nh(left, right) == core_nh(left, right), f"node_hash mismatch at i={i}"

    def test_empty_root_matches_core(self) -> None:
        from aevum.core.audit.merkle import EMPTY_ROOT as core_er

        from aevum.verify._core import EMPTY_ROOT as v_er
        assert v_er == core_er


# ---------------------------------------------------------------------------
# recompute_root — round-trip with aevum-core MerkleTree
# ---------------------------------------------------------------------------

class TestRecomputeRoot:
    def test_recompute_root_matches_core_for_hybrid_chain(self) -> None:
        """recompute_root(events) == aevum-core MerkleTree(digests).root()."""
        pytest.importorskip("oqs")
        from aevum.core.audit.merkle import MerkleTree
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify._core import recompute_root

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        events = [chain.new_event(event_type=f"e.{i}", payload={"i": i}, actor="test") for i in range(5)]

        from aevum.core.audit.event import AuditEvent
        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(e)) for e in events]
        core_root = MerkleTree(digests).root()
        verifier_root = recompute_root(events)
        assert verifier_root == core_root

    def test_recompute_root_empty_is_empty_root(self) -> None:
        from aevum.verify._core import EMPTY_ROOT, recompute_root
        assert recompute_root([]) == EMPTY_ROOT


# ---------------------------------------------------------------------------
# Conformance: verify_inclusion agrees with aevum-core
# ---------------------------------------------------------------------------

class TestInclusionConformance:
    @pytest.mark.parametrize("n", range(1, 13))
    def test_valid_inclusion_both_agree_true(self, n: int) -> None:
        from aevum.core.audit.merkle import MerkleTree
        from aevum.core.audit.merkle import verify_inclusion as core_vi

        from aevum.verify._core import leaf_hash
        from aevum.verify._core import verify_inclusion as v_vi

        tree = MerkleTree(_D[:n])
        root = tree.root()
        for i in range(n):
            proof = tree.inclusion_proof(i)
            lh = leaf_hash(_D[i])
            core_result = core_vi(lh, i, n, proof, root)
            v_result = v_vi(lh, i, n, proof, root)
            assert core_result is True and v_result is True, (
                f"n={n}, i={i}: core={core_result}, verifier={v_result}"
            )

    def test_tampered_leaf_both_agree_false(self) -> None:
        from aevum.core.audit.merkle import MerkleTree
        from aevum.core.audit.merkle import verify_inclusion as core_vi

        from aevum.verify._core import leaf_hash
        from aevum.verify._core import verify_inclusion as v_vi

        n = 8
        tree = MerkleTree(_D[:n])
        root = tree.root()
        bad_leaf = leaf_hash(bytes([0xFF] * 32))
        proof = tree.inclusion_proof(0)
        assert core_vi(bad_leaf, 0, n, proof, root) is False
        assert v_vi(bad_leaf, 0, n, proof, root) is False

    def test_wrong_index_both_agree_false(self) -> None:
        from aevum.core.audit.merkle import MerkleTree
        from aevum.core.audit.merkle import verify_inclusion as core_vi

        from aevum.verify._core import leaf_hash
        from aevum.verify._core import verify_inclusion as v_vi

        n = 6
        tree = MerkleTree(_D[:n])
        root = tree.root()
        proof = tree.inclusion_proof(0)
        lh = leaf_hash(_D[0])
        assert core_vi(lh, 1, n, proof, root) is False
        assert v_vi(lh, 1, n, proof, root) is False

    def test_index_out_of_range_false(self) -> None:
        from aevum.verify._core import leaf_hash
        from aevum.verify._core import verify_inclusion as v_vi
        assert v_vi(leaf_hash(_D[5]), 5, 5, [], bytes(32)) is False
        assert v_vi(leaf_hash(_D[0]), 99, 5, [], bytes(32)) is False

    def test_wrong_root_false(self) -> None:
        from aevum.core.audit.merkle import MerkleTree

        from aevum.verify._core import leaf_hash
        from aevum.verify._core import verify_inclusion as v_vi

        tree = MerkleTree(_D[:4])
        proof = tree.inclusion_proof(0)
        assert v_vi(leaf_hash(_D[0]), 0, 4, proof, bytes(32)) is False


# ---------------------------------------------------------------------------
# Conformance: verify_consistency agrees with aevum-core
# ---------------------------------------------------------------------------

class TestConsistencyConformance:
    @pytest.mark.parametrize("n", range(2, 13))
    def test_valid_consistency_both_agree_true(self, n: int) -> None:
        from aevum.core.audit.merkle import MerkleTree
        from aevum.core.audit.merkle import verify_consistency as core_vc

        from aevum.verify._core import verify_consistency as v_vc

        new_tree = MerkleTree(_D[:n])
        new_root = new_tree.root()
        for m in range(1, n):
            old_root = MerkleTree(_D[:m]).root()
            proof = new_tree.consistency_proof(m)
            core_result = core_vc(m, n, old_root, new_root, proof)
            v_result = v_vc(m, n, old_root, new_root, proof)
            assert core_result is True and v_result is True, (
                f"m={m}, n={n}: core={core_result}, verifier={v_result}"
            )

    def test_fork_detection_both_agree_false(self) -> None:
        """Modifying a historical entry: both verifiers return False (fork detection)."""
        from aevum.core.audit.merkle import MerkleTree
        from aevum.core.audit.merkle import verify_consistency as core_vc

        from aevum.verify._core import verify_consistency as v_vc

        m, n = 4, 8
        original = list(_D[:n])
        new_tree = MerkleTree(original)
        old_root_original = MerkleTree(original[:m]).root()
        proof = new_tree.consistency_proof(m)
        assert core_vc(m, n, old_root_original, new_tree.root(), proof) is True
        assert v_vc(m, n, old_root_original, new_tree.root(), proof) is True

        forked = list(original)
        forked[2] = hashlib.sha3_256(b"forged").digest()
        forked_tree = MerkleTree(forked)
        forked_proof = forked_tree.consistency_proof(m)

        assert core_vc(m, n, old_root_original, forked_tree.root(), forked_proof) is False
        assert v_vc(m, n, old_root_original, forked_tree.root(), forked_proof) is False

    def test_modify_historical_forked_proof_fails(self) -> None:
        """verifier fork detection: modify historical entry → consistency False."""
        from aevum.core.audit.merkle import MerkleTree

        from aevum.verify._core import verify_consistency as v_vc

        m, n = 3, 6
        original = list(_D[:n])
        original_new_root = MerkleTree(original).root()
        original_old_root = MerkleTree(original[:m]).root()

        forked = list(original)
        forked[1] = hashlib.sha3_256(b"evil").digest()
        forked_tree = MerkleTree(forked)
        forked_old_root = MerkleTree(forked[:m]).root()
        forked_proof = forked_tree.consistency_proof(m)

        assert v_vc(m, n, forked_old_root, original_new_root, forked_proof) is False
        assert v_vc(m, n, original_old_root, forked_tree.root(), forked_proof) is False


# ---------------------------------------------------------------------------
# STH + TSA helpers — require liboqs for hybrid STH tests
# ---------------------------------------------------------------------------

def _require_oqs() -> None:
    pytest.importorskip("oqs")


def _make_hybrid_sth(n: int = 4) -> tuple[object, bytes, bytes, list]:
    """Return (sth, ed25519_pub_bytes, mldsa65_pub_bytes, events) for a hybrid STH."""
    from aevum.core.audit.merkle import MerkleLog
    from aevum.core.audit.sigchain import Sigchain
    from aevum.core.signing import DualSigner

    ds = DualSigner.generate()
    signer = ds.as_primary_signer()
    chain = Sigchain(signer=signer, dual_signer=ds)
    events = [chain.new_event(event_type=f"e.{i}", payload={"i": i}, actor="test") for i in range(n)]
    mlog = MerkleLog(signer=signer, dual_signer=ds)
    sth = mlog.signed_tree_head(events)
    return sth, signer.public_key_bytes(), ds.mldsa65_public_key, events


# ---------------------------------------------------------------------------
# Fixtures: mock TSA root cert + token (no network, openssl subprocess)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock_tsa(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Create a self-signed TSA cert and a mock token for a 32-byte root hash."""
    d = tmp_path_factory.mktemp("tsa")
    root_bytes = bytes(range(32))  # dummy root hash for fixture token

    # Self-signed TSA key + cert (CA=true so it can be both root and signer)
    subprocess.run(
        ["openssl", "genrsa", "-out", str(d / "tsa.key"), "2048"],
        capture_output=True, check=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", str(d / "tsa.key"),
            "-out", str(d / "tsa.crt"),
            "-subj", "/CN=Mock TSA",
            "-days", "3650",
            "-addext", "extendedKeyUsage=critical,timeStamping",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ],
        capture_output=True, check=True,
    )

    (d / "serial").write_text("01\n")
    tsa_conf = (
        "[ tsa ]\ndefault_tsa = cfg\n"
        "[ cfg ]\n"
        f"dir = {d}\n"
        f"serial = {d}/serial\n"
        "crypto_device = builtin\n"
        f"signer_cert = {d}/tsa.crt\n"
        f"signer_key = {d}/tsa.key\n"
        "signer_digest = sha256\n"
        "default_policy = 1.2.3.4.5.6.7.8\n"
        "digests = sha256\n"
        "accuracy = secs:1\n"
        "ordering = no\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n"
    )
    (d / "tsa.conf").write_text(tsa_conf)

    (d / "root.bin").write_bytes(root_bytes)
    subprocess.run(
        ["openssl", "ts", "-query", "-data", str(d / "root.bin"),
         "-no_nonce", "-sha256", "-out", str(d / "req.tsq")],
        capture_output=True, check=True,
    )
    r = subprocess.run(
        ["openssl", "ts", "-reply", "-config", str(d / "tsa.conf"),
         "-queryfile", str(d / "req.tsq"), "-out", str(d / "resp.tsr")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"openssl ts -reply failed: {r.stderr}"

    tsa_cert_pem = (d / "tsa.crt").read_bytes()
    tsa_token_hex = (d / "resp.tsr").read_bytes().hex()
    return {
        "root_bytes": root_bytes,
        "tsa_cert_pem": tsa_cert_pem,
        "tsa_token_hex": tsa_token_hex,
    }


def _make_sth_with_tsa(root_hex: str, tsa_token_hex: str) -> object:
    """Minimal _STHLike with tsa_token set, used for TSA tests."""
    import types
    sth = types.SimpleNamespace(
        tree_size=1,
        root_hash=root_hex,
        timestamp=0,
        log_id="aa" * 32,
        hash_alg="sha3-256",
        key_scheme="ed25519+ml-dsa-65",
        ed25519_sig="AA==",
        mldsa65_sig="00" * 32,
        mldsa65_pub="00" * 32,
        ed25519_pub="00" * 32,
        tsa_token=tsa_token_hex,
    )
    return sth


# ---------------------------------------------------------------------------
# STH signature tests (hybrid — require liboqs)
# ---------------------------------------------------------------------------

class TestVerifySth:
    def setup_method(self) -> None:
        _require_oqs()

    def test_valid_hybrid_sth_verifies(self) -> None:
        from aevum.verify._core import recompute_root, verify_sth
        sth, ed_pub, ml_pub, events = _make_hybrid_sth()
        root = recompute_root(events)
        assert verify_sth(sth, ed25519_pub=ed_pub, mldsa65_pub=ml_pub, expected_root=root) is True

    def test_wrong_ed25519_key_fails(self) -> None:
        from aevum.core.signing import DualSigner

        from aevum.verify._core import verify_sth
        sth, _, ml_pub, _ = _make_hybrid_sth()
        wrong_key = DualSigner.generate().as_primary_signer().public_key_bytes()
        assert verify_sth(sth, ed25519_pub=wrong_key, mldsa65_pub=ml_pub) is False

    def test_no_mldsa65_pub_fails(self) -> None:
        from aevum.verify._core import verify_sth
        sth, ed_pub, _, _ = _make_hybrid_sth()
        assert verify_sth(sth, ed25519_pub=ed_pub, mldsa65_pub=None) is False

    def test_wrong_mldsa65_key_fails(self) -> None:
        from aevum.core.signing import DualSigner

        from aevum.verify._core import verify_sth
        sth, ed_pub, _, _ = _make_hybrid_sth()
        wrong_ml_pub = DualSigner.generate().mldsa65_public_key
        assert verify_sth(sth, ed25519_pub=ed_pub, mldsa65_pub=wrong_ml_pub) is False

    def test_sth_root_neq_recomputed_fails(self) -> None:
        """STH root ≠ recomputed root → False (tampered entry or wrong STH)."""
        from aevum.verify._core import verify_sth
        sth, ed_pub, ml_pub, _ = _make_hybrid_sth()
        bad_root = bytes([0xFF] * 32)
        assert verify_sth(sth, ed25519_pub=ed_pub, mldsa65_pub=ml_pub, expected_root=bad_root) is False

    def test_tampered_entry_recomputed_root_mismatch(self) -> None:
        """Tamper an entry → recompute_root returns different root → mismatch detected."""
        from aevum.verify._core import recompute_root, verify_sth
        sth, ed_pub, ml_pub, events = _make_hybrid_sth(4)
        tampered = list(events)
        tampered[1] = dataclasses.replace(events[1], actor="forged-actor")
        bad_root = recompute_root(tampered)
        # The STH root was computed over the originals — the tampered root won't match
        assert bytes.fromhex(sth.root_hash) != bad_root
        assert verify_sth(sth, ed25519_pub=ed_pub, mldsa65_pub=ml_pub, expected_root=bad_root) is False

    def test_verify_sth_conformance_matches_core(self) -> None:
        """verify_sth and aevum-core MerkleLog.verify_sth agree on valid STH."""
        from aevum.core.audit.merkle import MerkleLog
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify._core import verify_sth

        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="t", payload={}, actor="test") for _ in range(3)]
        mlog = MerkleLog(signer=signer, dual_signer=ds)
        sth = mlog.signed_tree_head(events)

        core_ok = mlog.verify_sth(sth)
        verifier_ok = verify_sth(sth, ed25519_pub=signer.public_key_bytes(), mldsa65_pub=ds.mldsa65_public_key)
        assert core_ok is True, "aevum-core must accept the STH"
        assert verifier_ok is True, "verifier must accept the same STH"


# ---------------------------------------------------------------------------
# TSA full chain tests (mocked — no network)
# ---------------------------------------------------------------------------

class TestVerifySthTsaFull:
    def test_valid_token_returns_true(self, mock_tsa: dict) -> None:
        from aevum.verify._core import verify_sth_tsa_full
        root_hex = mock_tsa["root_bytes"].hex()
        sth = _make_sth_with_tsa(root_hex, mock_tsa["tsa_token_hex"])
        result = verify_sth_tsa_full(sth, tsa_root_cert=mock_tsa["tsa_cert_pem"])
        assert result is True

    def test_no_tsa_token_returns_none(self, mock_tsa: dict) -> None:
        import types

        from aevum.verify._core import verify_sth_tsa_full
        sth = types.SimpleNamespace(tsa_token=None, root_hash="aa" * 32)
        result = verify_sth_tsa_full(sth, tsa_root_cert=mock_tsa["tsa_cert_pem"])
        assert result is None

    def test_wrong_root_in_sth_returns_false(self, mock_tsa: dict) -> None:
        """STH root_hash doesn't match the token's imprint → False."""
        from aevum.verify._core import verify_sth_tsa_full
        # Use a different root_hash than what the token was built over
        wrong_root_hex = (bytes([0xFF] * 32)).hex()
        sth = _make_sth_with_tsa(wrong_root_hex, mock_tsa["tsa_token_hex"])
        result = verify_sth_tsa_full(sth, tsa_root_cert=mock_tsa["tsa_cert_pem"])
        assert result is False

    def test_wrong_anchor_cert_returns_false(self, mock_tsa: dict, tmp_path: Path) -> None:
        """Token does not chain to the wrong root cert → False."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from aevum.verify._core import verify_sth_tsa_full

        # Generate a completely different root cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
        wrong_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        wrong_cert_pem = wrong_cert.public_bytes(serialization.Encoding.PEM)

        root_hex = mock_tsa["root_bytes"].hex()
        sth = _make_sth_with_tsa(root_hex, mock_tsa["tsa_token_hex"])
        result = verify_sth_tsa_full(sth, tsa_root_cert=wrong_cert_pem)
        assert result is False

    def test_tampered_token_hex_returns_false(self, mock_tsa: dict) -> None:
        """Corrupted token bytes → decode failure → False."""
        from aevum.verify._core import verify_sth_tsa_full
        bad_token_hex = "deadbeef" * 8
        sth = _make_sth_with_tsa(mock_tsa["root_bytes"].hex(), bad_token_hex)
        result = verify_sth_tsa_full(sth, tsa_root_cert=mock_tsa["tsa_cert_pem"])
        assert result is False
