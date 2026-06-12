# SPDX-License-Identifier: Apache-2.0
"""P2h gate tests: Merkle tree + Signed Tree Head.

Test inventory:
  leaf/node hashing — exact bytes for the 0x00/0x01 construction
  MTH small trees (hand-verified) — n=0,1,2,3,4 exact roots
  determinism — same events → same root
  tamper — reordered events → different root; mutated entry → different root
  STH hybrid-signed — verify_sth True WITH liboqs (PASSED not skipped)
  cross-domain separation — entry sig ≠ STH sig (distinct domain prefixes)
  ML-DSA-stripped STH — verify_sth fails closed
  MerkleLog without dual_signer — RuntimeError on signed_tree_head
  STH root matches independent MerkleTree computation
  base regression — verify_chain (linear) still passes unchanged
  P2i TSA anchor — tsa_token populated when client provided (mocked, no real network)
  P2i TSA anchor — tsa_token None when client absent or failing
  P2i TSA anchor — verify_sth_tsa imprint matches root (mocked decode)
  P2i TSA anchor — verify_sth_tsa None when no token; False on wrong imprint
  P2i TSA anchor — hybrid signature valid regardless of tsa_token presence
  P2i TSA anchor — sth.timestamp and sth.tsa_token are independent fields
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
from unittest.mock import MagicMock, patch

import pytest

from aevum.core.audit.event import DOMAIN_PREFIX, AuditEvent
from aevum.core.audit.merkle import (
    EMPTY_ROOT,
    STH_DOMAIN,
    MerkleLog,
    MerkleTree,
    SignedTreeHead,
    _sth_fields,
    leaf_hash,
    node_hash,
    sth_representative,
    verify_sth_tsa,
)
from aevum.core.audit.sigchain import Sigchain
from aevum.core.tsa import TSAToken

try:
    import oqs as _oqs_check  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


# ---------------------------------------------------------------------------
# Leaf / node hashing — exact bytes
# ---------------------------------------------------------------------------

class TestLeafNodeHashExactBytes:
    def test_leaf_hash_is_sha3_256_of_0x00_prefix(self) -> None:
        entry = bytes(range(32))
        expected = hashlib.sha3_256(b"\x00" + entry).digest()
        assert leaf_hash(entry) == expected

    def test_leaf_hash_zero_input(self) -> None:
        entry = bytes(32)
        expected = hashlib.sha3_256(b"\x00" + entry).digest()
        assert leaf_hash(entry) == expected

    def test_node_hash_is_sha3_256_of_0x01_prefix(self) -> None:
        left = bytes(range(32))
        right = bytes(range(32, 64))
        expected = hashlib.sha3_256(b"\x01" + left + right).digest()
        assert node_hash(left, right) == expected

    def test_leaf_and_node_hashes_differ_for_same_input(self) -> None:
        """Different domain bytes must produce different hashes for the same payload."""
        data = bytes(32)
        assert leaf_hash(data) != node_hash(data, data)

    def test_empty_root_constant(self) -> None:
        assert hashlib.sha3_256(b"").digest() == EMPTY_ROOT
        assert len(EMPTY_ROOT) == 32

    def test_leaf_hash_length_is_32(self) -> None:
        assert len(leaf_hash(bytes(32))) == 32

    def test_node_hash_length_is_32(self) -> None:
        assert len(node_hash(bytes(32), bytes(32))) == 32


# ---------------------------------------------------------------------------
# MTH small trees (n=0,1,2,3,4) — hand-verified against RFC 6962 §2.1
# ---------------------------------------------------------------------------

class TestMTHSmallTrees:
    """Hand-verified MTH roots for n=0..4.

    RFC 6962 §2.1 split rule: k = largest power of 2 < n
      n=2: k=1 → [d0]|[d1]
      n=3: k=2 → [d0,d1]|[d2]
      n=4: k=2 → [d0,d1]|[d2,d3]
    """

    # Fixed 32-byte entry digests for reproducibility
    _D = [bytes([i] * 32) for i in range(8)]

    def test_n0_is_empty_root(self) -> None:
        tree = MerkleTree([])
        assert tree.root() == EMPTY_ROOT
        assert tree.size == 0

    def test_n1_is_leaf_of_d0(self) -> None:
        tree = MerkleTree([self._D[0]])
        assert tree.root() == leaf_hash(self._D[0])
        assert tree.size == 1

    def test_n2_is_node_of_two_leaves(self) -> None:
        d0, d1 = self._D[0], self._D[1]
        tree = MerkleTree([d0, d1])
        expected = node_hash(leaf_hash(d0), leaf_hash(d1))
        assert tree.root() == expected
        assert tree.size == 2

    def test_n3_right_subtree_is_single_leaf(self) -> None:
        d0, d1, d2 = self._D[0], self._D[1], self._D[2]
        tree = MerkleTree([d0, d1, d2])
        # k=2: MTH([d0,d1,d2]) = node(node(leaf(d0),leaf(d1)), leaf(d2))
        expected = node_hash(
            node_hash(leaf_hash(d0), leaf_hash(d1)),
            leaf_hash(d2),
        )
        assert tree.root() == expected
        assert tree.size == 3

    def test_n4_balanced_tree(self) -> None:
        d0, d1, d2, d3 = self._D[0], self._D[1], self._D[2], self._D[3]
        tree = MerkleTree([d0, d1, d2, d3])
        # k=2: MTH([d0..d3]) = node(node(leaf(d0),leaf(d1)), node(leaf(d2),leaf(d3)))
        expected = node_hash(
            node_hash(leaf_hash(d0), leaf_hash(d1)),
            node_hash(leaf_hash(d2), leaf_hash(d3)),
        )
        assert tree.root() == expected
        assert tree.size == 4

    def test_n5_split_at_4(self) -> None:
        ds = self._D[:5]
        tree = MerkleTree(ds)
        # k=4 (largest power of 2 < 5): [d0..d3] | [d4]
        left = node_hash(
            node_hash(leaf_hash(ds[0]), leaf_hash(ds[1])),
            node_hash(leaf_hash(ds[2]), leaf_hash(ds[3])),
        )
        right = leaf_hash(ds[4])
        expected = node_hash(left, right)
        assert tree.root() == expected


# ---------------------------------------------------------------------------
# Determinism and tamper detection
# ---------------------------------------------------------------------------

class TestDeterminismAndTamper:
    def test_same_digests_produce_same_root(self) -> None:
        ds = [bytes([i] * 32) for i in range(5)]
        assert MerkleTree(ds).root() == MerkleTree(ds).root()

    def test_same_events_produce_same_root(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(4)
        ]
        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(e)) for e in events]
        assert MerkleTree(digests).root() == MerkleTree(digests).root()

    def test_reordered_events_different_root(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(e)) for e in events]
        reordered = [digests[2], digests[0], digests[1]]
        # Only meaningful if digests are distinct (they should be — different event_id/seq)
        if digests != reordered:
            assert MerkleTree(digests).root() != MerkleTree(reordered).root()

    def test_mutated_entry_changes_root(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(e)) for e in events]
        original_root = MerkleTree(digests).root()

        # Mutate the middle event (any field change changes the hash)
        mutated = dataclasses.replace(events[1], event_type="tampered")
        new_digests = [
            digests[0],
            bytes.fromhex(AuditEvent.hash_event_for_chain(mutated)),
            digests[2],
        ]
        assert MerkleTree(new_digests).root() != original_root

    def test_appended_entry_changes_root(self) -> None:
        ds = [bytes([i] * 32) for i in range(3)]
        root3 = MerkleTree(ds).root()
        root4 = MerkleTree(ds + [bytes([99] * 32)]).root()
        assert root3 != root4


# ---------------------------------------------------------------------------
# STH: hybrid-signed, verify_sth, cross-domain, ML-DSA-stripped
# ---------------------------------------------------------------------------

class TestSignedTreeHead:
    @needs_liboqs
    def test_sth_verify_true_with_liboqs(self) -> None:
        """verify_sth must return True WITH liboqs — PASSED not skipped."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [
            chain.new_event(event_type=f"sth.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head(events)
        assert log.verify_sth(sth) is True

    @needs_liboqs
    def test_sth_tree_size_and_root_match_independent_tree(self) -> None:
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [
            chain.new_event(event_type=f"sth.root.{i}", payload={}, actor="a")
            for i in range(4)
        ]
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head(events)

        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(e)) for e in events]
        independent_root = MerkleTree(digests).root()

        assert sth.tree_size == 4
        assert sth.root_hash == independent_root.hex()

    @needs_liboqs
    def test_sth_empty_tree(self) -> None:
        """STH over an empty event list encodes EMPTY_ROOT."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head([])
        assert sth.tree_size == 0
        assert sth.root_hash == EMPTY_ROOT.hex()
        assert log.verify_sth(sth) is True

    @needs_liboqs
    def test_sth_fields_metadata(self) -> None:
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head([])
        assert sth.hash_alg == "sha3-256"
        assert sth.key_scheme == "ed25519+ml-dsa-65"
        assert sth.log_id == signer.key_id
        assert sth.ed25519_pub == signer.public_key_bytes().hex()

    def test_no_dual_signer_raises(self) -> None:
        """MerkleLog without dual_signer must raise RuntimeError on signed_tree_head."""
        chain = Sigchain()
        log = MerkleLog(signer=chain._signer)
        with pytest.raises(RuntimeError, match="DualSigner"):
            log.signed_tree_head([])


# ---------------------------------------------------------------------------
# Cross-domain separation
# ---------------------------------------------------------------------------

class TestCrossDomainSeparation:
    def test_domain_prefixes_are_distinct(self) -> None:
        assert DOMAIN_PREFIX != STH_DOMAIN
        assert DOMAIN_PREFIX == b"aevum-sigchain-v1\x00"
        assert STH_DOMAIN == b"aevum-sth-v1\x00"

    @needs_liboqs
    def test_entry_sig_does_not_verify_as_sth(self) -> None:
        """An entry's Ed25519 signature must not verify against the STH digest."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="domain.sep", payload={}, actor="a")]

        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head(events)

        # Take the entry's primary Ed25519 signature
        entry = events[0]
        entry_sig_bytes = base64.urlsafe_b64decode(entry.signature + "==")

        # Reconstruct the STH representative and its digest
        sth_fields = _sth_fields(
            tree_size=sth.tree_size,
            root_hash=sth.root_hash,
            timestamp=sth.timestamp,
            log_id=sth.log_id,
            hash_alg=sth.hash_alg,
            key_scheme=sth.key_scheme,
        )
        sth_rep = sth_representative(sth_fields)
        sth_digest = hashlib.sha3_256(sth_rep).digest()

        # The entry signature must NOT verify over the STH digest
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sth.ed25519_pub))
        with pytest.raises(InvalidSignature):
            pub.verify(entry_sig_bytes, sth_digest)

    @needs_liboqs
    def test_sth_sig_does_not_verify_as_entry(self) -> None:
        """The STH's Ed25519 signature must not verify against an entry digest."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="domain.sep2", payload={}, actor="a")]

        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head(events)

        # STH Ed25519 signature
        sth_sig_bytes = base64.urlsafe_b64decode(sth.ed25519_sig + "==")

        # Entry digest (what the entry's Ed25519 signature was made over)
        entry_digest = bytes.fromhex(AuditEvent.hash_event_for_chain(events[0]))

        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sth.ed25519_pub))
        with pytest.raises(InvalidSignature):
            pub.verify(sth_sig_bytes, entry_digest)


# ---------------------------------------------------------------------------
# Fail-closed: ML-DSA-65 stripped → verify_sth returns False
# ---------------------------------------------------------------------------

class TestSTHFailClosed:
    @needs_liboqs
    def test_mldsa_stripped_fails_closed(self) -> None:
        """verify_sth must return False when ML-DSA-65 signature is invalid."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [
            chain.new_event(event_type="fail.closed", payload={}, actor="a")
            for _ in range(2)
        ]
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head(events)
        assert log.verify_sth(sth) is True

        # Replace ML-DSA sig with all-zero bytes (almost certainly invalid)
        bad_sth = dataclasses.replace(sth, mldsa65_sig="00" * 3309)
        assert log.verify_sth(bad_sth) is False

    @needs_liboqs
    def test_ed25519_tampered_fails_closed(self) -> None:
        """verify_sth must return False when Ed25519 signature is invalid."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="fail.ed", payload={}, actor="a")]
        sth = log.signed_tree_head(events)

        # Corrupt the Ed25519 signature
        bad_sig = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
        bad_sth = dataclasses.replace(sth, ed25519_sig=bad_sig)
        assert log.verify_sth(bad_sth) is False

    @needs_liboqs
    def test_tampered_root_hash_fails(self) -> None:
        """verify_sth must return False if root_hash is altered (representative changes)."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="tamper.root", payload={}, actor="a")]
        sth = log.signed_tree_head(events)

        # Tamper the root hash — the representative changes, signatures no longer match
        bad_sth = dataclasses.replace(sth, root_hash="ff" * 32)
        assert log.verify_sth(bad_sth) is False


# ---------------------------------------------------------------------------
# Base regression: verify_chain (linear) still passes unchanged
# ---------------------------------------------------------------------------

class TestBaseRegression:
    def test_classical_verify_chain_still_passes(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"reg.{i}", payload={"i": i}, actor="a")
            for i in range(5)
        ]
        assert chain.verify_chain(events) is True

    @needs_liboqs
    def test_hybrid_verify_chain_still_passes(self) -> None:
        """Hybrid verify_chain must remain PASSED (not skipped) WITH liboqs."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        events = [
            chain.new_event(event_type=f"reg.hybrid.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert all(e.key_scheme == "ed25519+ml-dsa-65" for e in events)
        assert chain.verify_chain(events) is True

    def test_merkle_complication_does_not_affect_sigchain(self) -> None:
        """Importing merkle.py does not alter Sigchain or AuditEvent behavior."""
        chain = Sigchain()
        event = chain.new_event(event_type="import.test", payload={}, actor="a")
        assert chain.verify_chain([event]) is True
        # Merkle tree over the same event still works independently
        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(event))]
        tree = MerkleTree(digests)
        assert tree.size == 1
        assert tree.root() == leaf_hash(digests[0])


# ---------------------------------------------------------------------------
# P2i: STH TSA anchor — RFC 3161 timestamp over the Merkle root
# All tests mock the TSA client or decode_timestamp_response; no real network
# request is ever made (confirmed by using MagicMock instead of TSAClient).
# ---------------------------------------------------------------------------

def _make_mock_tsa(token_bytes: bytes) -> MagicMock:
    """Return a mock TSAClient whose .timestamp() returns a TSAToken with token_bytes."""
    mock_tsa = MagicMock()
    mock_tsa.timestamp.return_value = TSAToken(tsa_url="mock://tsa", token_bytes=token_bytes)
    return mock_tsa


def _make_failing_mock_tsa() -> MagicMock:
    """Return a mock TSAClient whose .timestamp() returns None (simulates TSA failure)."""
    mock_tsa = MagicMock()
    mock_tsa.timestamp.return_value = None
    return mock_tsa


def _mock_decode_response(root_bytes: bytes, algo: str = "sha512") -> MagicMock:
    """Build a mock decode_timestamp_response return value for verify_sth_tsa tests."""
    expected_hash = hashlib.new(algo, root_bytes).digest()
    oid_map = {"sha512": "2.16.840.1.101.3.4.2.3", "sha256": "2.16.840.1.101.3.4.2.1"}

    mock_imprint = MagicMock()
    mock_imprint.hash_algorithm.dotted_string = oid_map[algo]
    mock_imprint.message = expected_hash

    mock_response = MagicMock()
    mock_response.tst_info.message_imprint = mock_imprint
    return mock_response


class TestSTHTSAToken:
    """P2i gate tests for STH TSA anchoring."""

    _FAKE_TOKEN_BYTES = b"\x30\x82\x01\x00" + bytes(100)  # opaque fake DER

    @needs_liboqs
    def test_tsa_token_populated_when_client_provided(self) -> None:
        """signed_tree_head with tsa_client must attach tsa_token (mock — no real TSA)."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="tsa.anchor", payload={}, actor="a")]
        log = MerkleLog(signer=signer, dual_signer=ds)

        mock_tsa = _make_mock_tsa(self._FAKE_TOKEN_BYTES)
        sth = log.signed_tree_head(events, tsa_client=mock_tsa)

        assert sth.tsa_token == self._FAKE_TOKEN_BYTES.hex()
        # Confirm mock was called with the raw Merkle root bytes (32 bytes)
        called_data = mock_tsa.timestamp.call_args[0][0]
        assert len(called_data) == 32
        assert called_data == bytes.fromhex(sth.root_hash)

    @needs_liboqs
    def test_tsa_token_none_when_no_client(self) -> None:
        """signed_tree_head without tsa_client → tsa_token is None."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head([])
        assert sth.tsa_token is None

    @needs_liboqs
    def test_tsa_token_none_when_client_returns_none(self) -> None:
        """TSA failure (client returns None) → tsa_token None, STH still produced."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head([], tsa_client=_make_failing_mock_tsa())
        assert sth.tsa_token is None

    @needs_liboqs
    def test_tsa_token_none_when_client_raises(self) -> None:
        """Unexpected TSA exception is caught; tsa_token None, STH still returned."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        mock_tsa = MagicMock()
        mock_tsa.timestamp.side_effect = RuntimeError("boom")
        sth = log.signed_tree_head([], tsa_client=mock_tsa)
        assert sth.tsa_token is None

    @needs_liboqs
    def test_sth_verify_still_valid_with_tsa_token(self) -> None:
        """verify_sth must return True even when tsa_token is present."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        chain = Sigchain(signer=signer, dual_signer=ds)
        events = [chain.new_event(event_type="tsa.valid", payload={}, actor="a")]
        log = MerkleLog(signer=signer, dual_signer=ds)

        sth = log.signed_tree_head(events, tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
        assert sth.tsa_token is not None
        assert log.verify_sth(sth) is True

    @needs_liboqs
    def test_sth_verify_still_valid_without_tsa_token(self) -> None:
        """verify_sth must return True when tsa_token is absent (graceful degradation)."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)
        sth = log.signed_tree_head([])
        assert sth.tsa_token is None
        assert log.verify_sth(sth) is True

    @needs_liboqs
    def test_timestamp_and_tsa_token_are_independent(self) -> None:
        """sth.timestamp (self-asserted) and sth.tsa_token (external) are both present."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        sth = log.signed_tree_head([], tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
        assert isinstance(sth.timestamp, int)   # self-asserted Unix seconds
        assert sth.tsa_token is not None        # external RFC 3161 attestation
        # They are distinct fields; neither collapses the other
        assert sth.timestamp != sth.tsa_token

    def test_verify_sth_tsa_returns_none_when_no_token(self) -> None:
        """verify_sth_tsa must return None when tsa_token is absent."""
        # Build a minimal STH with all required fields and tsa_token=None
        sth = SignedTreeHead(
            tree_size=0,
            root_hash="a" * 64,
            timestamp=1000000,
            log_id="b" * 64,
            hash_alg="sha3-256",
            key_scheme="ed25519+ml-dsa-65",
            ed25519_sig="c" * 86,
            mldsa65_sig="d" * 6618,
            mldsa65_pub="e" * 3904,
            ed25519_pub="f" * 64,
            tsa_token=None,
        )
        assert verify_sth_tsa(sth) is None

    @needs_liboqs
    def test_verify_sth_tsa_imprint_matches_root(self) -> None:
        """verify_sth_tsa returns True when mock imprint matches root hash bytes."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        sth = log.signed_tree_head([], tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
        assert sth.tsa_token is not None

        root_bytes = bytes.fromhex(sth.root_hash)
        mock_response = _mock_decode_response(root_bytes, algo="sha512")

        with patch("aevum.core.audit.merkle.decode_timestamp_response", return_value=mock_response):
            result = verify_sth_tsa(sth)

        assert result is True

    @needs_liboqs
    def test_verify_sth_tsa_wrong_imprint_returns_false(self) -> None:
        """verify_sth_tsa returns False when the message imprint does not match the root."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        sth = log.signed_tree_head([], tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
        assert sth.tsa_token is not None

        # Build a mock response where the message imprint is all zeros (wrong hash)
        mock_imprint = MagicMock()
        mock_imprint.hash_algorithm.dotted_string = "2.16.840.1.101.3.4.2.3"  # sha512
        mock_imprint.message = bytes(64)  # wrong — not sha512(root_bytes)

        mock_response = MagicMock()
        mock_response.tst_info.message_imprint = mock_imprint

        with patch("aevum.core.audit.merkle.decode_timestamp_response", return_value=mock_response):
            result = verify_sth_tsa(sth)

        assert result is False

    @needs_liboqs
    def test_verify_sth_tsa_sha256_imprint(self) -> None:
        """verify_sth_tsa handles SHA-256 OID as well as SHA-512."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        sth = log.signed_tree_head([], tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
        assert sth.tsa_token is not None

        root_bytes = bytes.fromhex(sth.root_hash)
        mock_response = _mock_decode_response(root_bytes, algo="sha256")

        with patch("aevum.core.audit.merkle.decode_timestamp_response", return_value=mock_response):
            result = verify_sth_tsa(sth)

        assert result is True

    @needs_liboqs
    def test_verify_sth_tsa_unknown_oid_returns_false(self) -> None:
        """verify_sth_tsa returns False for an unrecognised hash algorithm OID."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        sth = log.signed_tree_head([], tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
        assert sth.tsa_token is not None

        mock_imprint = MagicMock()
        mock_imprint.hash_algorithm.dotted_string = "1.2.3.4.5.99"  # unknown OID
        mock_imprint.message = bytes(32)

        mock_response = MagicMock()
        mock_response.tst_info.message_imprint = mock_imprint

        with patch("aevum.core.audit.merkle.decode_timestamp_response", return_value=mock_response):
            result = verify_sth_tsa(sth)

        assert result is False

    @needs_liboqs
    def test_no_real_tsa_network_request_in_tests(self) -> None:
        """Confirm that no real httpx.post is made when using the mock TSA client."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        signer = ds.as_primary_signer()
        log = MerkleLog(signer=signer, dual_signer=ds)

        with patch("aevum.core.tsa.httpx.post") as mock_http:
            sth = log.signed_tree_head([], tsa_client=_make_mock_tsa(self._FAKE_TOKEN_BYTES))
            mock_http.assert_not_called()

        assert sth.tsa_token == self._FAKE_TOKEN_BYTES.hex()
