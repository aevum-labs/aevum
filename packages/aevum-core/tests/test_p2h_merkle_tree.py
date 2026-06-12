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
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib

import pytest

from aevum.core.audit.event import DOMAIN_PREFIX, AuditEvent
from aevum.core.audit.merkle import (
    EMPTY_ROOT,
    STH_DOMAIN,
    MerkleLog,
    MerkleTree,
    _sth_fields,
    leaf_hash,
    node_hash,
    sth_representative,
)
from aevum.core.audit.sigchain import Sigchain

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
