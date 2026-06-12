# SPDX-License-Identifier: Apache-2.0
"""P2h-2 gate tests: inclusion proofs + consistency proofs.

Test inventory:
  Inclusion round-trip exhaustive — n=1..16 every index
  Inclusion verifier independence — recomputed root == tree.root(), never calls _mth
  Inclusion hand-checked — n=2 (leaf0), n=3 (leaf0,1,2), n=4 (leaf1) exact path contents
  Inclusion tamper — wrong sibling / wrong index / wrong leaf / index>=n → False
  Consistency round-trip exhaustive — n=1..16, every m=1..n
  Consistency hand-checked — (m=1,n=2), (m=2,n=3), (m=2,n=4), (m=3,n=4) exact proofs
  Fork detection — append→True; modify historical entry→False (the security property)
  Consistency edges — m==n, m>n, m==0, mutated old_root/new_root/proof element
"""
from __future__ import annotations

import hashlib

import pytest

from aevum.core.audit.merkle import (
    MerkleTree,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)

# Fixed 32-byte entry digests (raw, pre-leaf_hash) for reproducibility
_D = [bytes([i] * 32) for i in range(20)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tree(n: int) -> MerkleTree:
    return MerkleTree(_D[:n])


def _lh(i: int) -> bytes:
    return leaf_hash(_D[i])


# ---------------------------------------------------------------------------
# Inclusion: exhaustive round-trip n=1..16
# ---------------------------------------------------------------------------

class TestInclusionRoundTrip:
    @pytest.mark.parametrize("n", range(1, 17))
    def test_every_index_verifies(self, n: int) -> None:
        tree = _tree(n)
        root = tree.root()
        for i in range(n):
            proof = tree.inclusion_proof(i)
            assert verify_inclusion(_lh(i), i, n, proof, root), (
                f"verify_inclusion failed for n={n}, i={i}"
            )

    @pytest.mark.parametrize("n", range(1, 17))
    def test_proof_length_is_ceil_log2(self, n: int) -> None:
        """Proof length is at most ceil(log2(n)) elements."""
        import math
        tree = _tree(n)
        max_len = math.ceil(math.log2(max(n, 2)))
        for i in range(n):
            assert len(tree.inclusion_proof(i)) <= max_len


# ---------------------------------------------------------------------------
# Inclusion: verifier independence (never calls _mth)
# ---------------------------------------------------------------------------

class TestInclusionVerifierIndependence:
    def test_verifier_recomputes_same_root_as_tree(self) -> None:
        """verify_inclusion recomputed root == tree.root() — two independent paths agree."""
        for n in range(1, 13):
            tree = _tree(n)
            tree_root = tree.root()
            for i in range(n):
                proof = tree.inclusion_proof(i)
                # Reconstruct root manually (same logic as verifier) — independent
                fn, sn = i, n - 1
                r = _lh(i)
                for step in proof:
                    if fn & 1 or fn == sn:
                        r = node_hash(step, r)
                        while fn != 0 and not (fn & 1):
                            fn >>= 1
                            sn >>= 1
                    else:
                        r = node_hash(r, step)
                    fn >>= 1
                    sn >>= 1
                assert r == tree_root, f"n={n}, i={i}: recomputed {r.hex()} != tree root {tree_root.hex()}"

    def test_verify_inclusion_does_not_call_mth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Patch _mth to raise — verify_inclusion must not call it."""
        def _banned(*_args: object, **_kwargs: object) -> bytes:
            raise AssertionError("verify_inclusion must not call MerkleTree._mth")

        monkeypatch.setattr(MerkleTree, "_mth", staticmethod(_banned))

        # Build proofs BEFORE patching root (tree.root() uses _mth via __init__)
        # So we pre-compute proofs and roots using a clean tree
        monkeypatch.undo()
        tree = _tree(4)
        root = tree.root()
        proofs = [tree.inclusion_proof(i) for i in range(4)]
        monkeypatch.setattr(MerkleTree, "_mth", staticmethod(_banned))

        for i in range(4):
            # This must not call _mth
            result = verify_inclusion(_lh(i), i, 4, proofs[i], root)
            assert result is True


# ---------------------------------------------------------------------------
# Inclusion: hand-checked exact proof contents
# ---------------------------------------------------------------------------

class TestInclusionHandChecked:
    def test_n2_leaf0_proof_is_leaf1(self) -> None:
        tree = _tree(2)
        assert tree.inclusion_proof(0) == [_lh(1)]

    def test_n2_leaf1_proof_is_leaf0(self) -> None:
        tree = _tree(2)
        assert tree.inclusion_proof(1) == [_lh(0)]

    def test_n3_leaf0_proof(self) -> None:
        # n=3, k=2; PATH(0,D[0:3]) = PATH(0,D[0:2]) + [leaf(d2)]
        #   PATH(0,D[0:2]) = [leaf(d1)]
        # = [leaf(d1), leaf(d2)]
        tree = _tree(3)
        assert tree.inclusion_proof(0) == [_lh(1), _lh(2)]

    def test_n3_leaf1_proof(self) -> None:
        # PATH(1,D[0:3]): k=2, m=1<k → PATH(1,D[0:2]) + [leaf(d2)]
        #   PATH(1,D[0:2]): k=1, m=1>=k → PATH(0,D[1:2]) + [leaf(d0)] = [leaf(d0)]
        # = [leaf(d0), leaf(d2)]
        tree = _tree(3)
        assert tree.inclusion_proof(1) == [_lh(0), _lh(2)]

    def test_n3_leaf2_proof(self) -> None:
        # PATH(2,D[0:3]): k=2, m=2>=k → PATH(0,D[2:3]) + [MTH(D[0:2])]
        #   PATH(0,D[2:3]): n=1 → []
        # = [node(leaf(d0), leaf(d1))]
        tree = _tree(3)
        assert tree.inclusion_proof(2) == [node_hash(_lh(0), _lh(1))]

    def test_n4_leaf1_proof(self) -> None:
        # PATH(1,D[0:4]): k=2, m=1<k → PATH(1,D[0:2]) + [MTH(D[2:4])]
        #   PATH(1,D[0:2]): k=1, m=1>=k → [leaf(d0)]
        # = [leaf(d0), node(leaf(d2), leaf(d3))]
        tree = _tree(4)
        assert tree.inclusion_proof(1) == [
            _lh(0),
            node_hash(_lh(2), _lh(3)),
        ]

    def test_n4_all_indices_correct_root(self) -> None:
        tree = _tree(4)
        root = node_hash(
            node_hash(_lh(0), _lh(1)),
            node_hash(_lh(2), _lh(3)),
        )
        assert tree.root() == root
        for i in range(4):
            assert verify_inclusion(_lh(i), i, 4, tree.inclusion_proof(i), root)


# ---------------------------------------------------------------------------
# Inclusion: tamper detection
# ---------------------------------------------------------------------------

class TestInclusionTamper:
    def _setup(self) -> tuple[MerkleTree, bytes]:
        tree = _tree(5)
        return tree, tree.root()

    def test_wrong_sibling_fails(self) -> None:
        tree, root = self._setup()
        for i in range(5):
            proof = tree.inclusion_proof(i)
            if proof:
                bad_proof = [bytes(32)] + proof[1:]
                assert verify_inclusion(_lh(i), i, 5, bad_proof, root) is False

    def test_wrong_leaf_fails(self) -> None:
        tree, root = self._setup()
        # Use a leaf that is definitely not _lh(0) — all-0xFF, distinct from _D[0]=0x00*32
        wrong_leaf = leaf_hash(bytes([0xFF] * 32))
        assert verify_inclusion(wrong_leaf, 0, 5, tree.inclusion_proof(0), root) is False

    def test_wrong_index_fails(self) -> None:
        tree, root = self._setup()
        # proof for index 0 used at index 1 should fail
        proof0 = tree.inclusion_proof(0)
        assert verify_inclusion(_lh(0), 1, 5, proof0, root) is False

    def test_index_out_of_range_fails(self) -> None:
        tree, root = self._setup()
        assert verify_inclusion(_lh(5), 5, 5, [], root) is False
        assert verify_inclusion(_lh(0), 99, 5, [], root) is False

    def test_wrong_root_fails(self) -> None:
        tree, root = self._setup()
        bad_root = bytes(32)
        assert verify_inclusion(_lh(0), 0, 5, tree.inclusion_proof(0), bad_root) is False

    def test_index_out_of_range_raises_on_proof_generation(self) -> None:
        tree = _tree(4)
        with pytest.raises(ValueError):
            tree.inclusion_proof(4)
        with pytest.raises(ValueError):
            tree.inclusion_proof(100)


# ---------------------------------------------------------------------------
# Consistency: exhaustive round-trip n=1..16
# ---------------------------------------------------------------------------

class TestConsistencyRoundTrip:
    @pytest.mark.parametrize("n", range(1, 17))
    def test_every_old_size_verifies(self, n: int) -> None:
        new_tree = _tree(n)
        new_root = new_tree.root()
        for m in range(1, n + 1):
            old_root = _tree(m).root()
            proof = new_tree.consistency_proof(m)
            assert verify_consistency(m, n, old_root, new_root, proof), (
                f"verify_consistency failed for m={m}, n={n}"
            )


# ---------------------------------------------------------------------------
# Consistency: hand-checked exact proof contents
# ---------------------------------------------------------------------------

class TestConsistencyHandChecked:
    def test_m1_n2(self) -> None:
        # PROOF(1, D[0:2]): SUBPROOF(1,D[0:2],true)
        #   k=1, m=1<=k → SUBPROOF(1,D[0:1],true) + [leaf(d1)]
        #     m==n, b=true → []
        #   = [leaf(d1)]
        tree = _tree(2)
        assert tree.consistency_proof(1) == [_lh(1)]

    def test_m2_n3(self) -> None:
        # PROOF(2, D[0:3]): k=2, m=2<=k → SUBPROOF(2,D[0:2],true) + [leaf(d2)]
        #   m==n, b=true → []
        # = [leaf(d2)]
        tree = _tree(3)
        assert tree.consistency_proof(2) == [_lh(2)]

    def test_m2_n4(self) -> None:
        # PROOF(2, D[0:4]): k=2, m=2<=k → SUBPROOF(2,D[0:2],true) + [MTH(D[2:4])]
        #   m==n, b=true → []
        # = [node(leaf(d2), leaf(d3))]
        tree = _tree(4)
        assert tree.consistency_proof(2) == [node_hash(_lh(2), _lh(3))]

    def test_m3_n4(self) -> None:
        # PROOF(3, D[0:4]): k=2, m=3>k → SUBPROOF(1,D[2:4],false) + [MTH(D[0:2])]
        #   SUBPROOF(1,D[2:4],false): k=1, m=1<=k → SUBPROOF(1,D[2:3],false) + [leaf(d3)]
        #     m==n, b=false → [leaf(d2)]
        #   = [leaf(d2), leaf(d3)]
        # = [leaf(d2), leaf(d3), node(leaf(d0), leaf(d1))]
        tree = _tree(4)
        assert tree.consistency_proof(3) == [
            _lh(2),
            _lh(3),
            node_hash(_lh(0), _lh(1)),
        ]

    def test_m1_n4_verifies_both_roots(self) -> None:
        tree = _tree(4)
        old_root = _tree(1).root()
        proof = tree.consistency_proof(1)
        # [leaf(d1), node(leaf(d2), leaf(d3))]
        assert proof == [_lh(1), node_hash(_lh(2), _lh(3))]
        assert verify_consistency(1, 4, old_root, tree.root(), proof)


# ---------------------------------------------------------------------------
# Fork detection — THE security property
# ---------------------------------------------------------------------------

class TestForkDetection:
    def test_append_is_consistent(self) -> None:
        """Growing the log produces a consistent proof."""
        for m in range(1, 8):
            old_tree = _tree(m)
            old_root = old_tree.root()
            for n in range(m + 1, m + 5):
                new_tree = _tree(n)
                proof = new_tree.consistency_proof(m)
                assert verify_consistency(m, n, old_root, new_tree.root(), proof), (
                    f"append broken: m={m}, n={n}"
                )

    def test_modify_historical_entry_fails_consistency(self) -> None:
        """Modifying a historical entry makes the old_root mismatch → False."""
        m = 4
        n = 8

        # Original log of size n
        original_digests = list(_D[:n])
        new_tree = MerkleTree(original_digests)
        old_root_original = MerkleTree(original_digests[:m]).root()
        proof = new_tree.consistency_proof(m)

        # The proof verifies with the original old_root
        assert verify_consistency(m, n, old_root_original, new_tree.root(), proof) is True

        # Now build a FORKED tree: modify entry 2 (within the first m entries)
        forked_digests = list(original_digests)
        forked_digests[2] = hashlib.sha3_256(b"forged-entry").digest()

        # The forked tree at size m has a different root
        old_root_forked = MerkleTree(forked_digests[:m]).root()
        assert old_root_forked != old_root_original

        # Consistency proof from the forked extended tree
        forked_tree = MerkleTree(forked_digests)
        forked_proof = forked_tree.consistency_proof(m)

        # Verifying the forked proof against the ORIGINAL old_root must return False
        assert verify_consistency(m, n, old_root_original, forked_tree.root(), forked_proof) is False

    def test_forked_proof_does_not_verify_against_original_new_root(self) -> None:
        """A fork cannot be made to look consistent with the original new tree."""
        m, n = 3, 6
        original_digests = list(_D[:n])
        original_new_root = MerkleTree(original_digests).root()
        original_old_root = MerkleTree(original_digests[:m]).root()

        # Forge: change a historical entry, get a "new" proof
        forked_digests = list(original_digests)
        forked_digests[1] = hashlib.sha3_256(b"evil").digest()
        forked_tree = MerkleTree(forked_digests)
        forked_old_root = MerkleTree(forked_digests[:m]).root()
        forked_proof = forked_tree.consistency_proof(m)

        # Forged old_root vs original new_root → False
        assert verify_consistency(m, n, forked_old_root, original_new_root, forked_proof) is False
        # Original old_root vs forged new_root with forged proof → False
        assert verify_consistency(m, n, original_old_root, forked_tree.root(), forked_proof) is False


# ---------------------------------------------------------------------------
# Consistency: edge cases
# ---------------------------------------------------------------------------

class TestConsistencyEdgeCases:
    def test_m_equals_n_returns_true_empty_proof(self) -> None:
        for n in range(1, 9):
            tree = _tree(n)
            root = tree.root()
            proof = tree.consistency_proof(n)
            assert proof == []
            assert verify_consistency(n, n, root, root, []) is True

    def test_m_greater_than_n_returns_false(self) -> None:
        assert verify_consistency(5, 4, bytes(32), bytes(32), []) is False
        assert verify_consistency(10, 1, bytes(32), bytes(32), []) is False

    def test_m_equals_zero_returns_true(self) -> None:
        assert verify_consistency(0, 5, bytes(32), bytes(32), []) is True
        assert verify_consistency(0, 0, bytes(32), bytes(32), []) is True

    def test_mutated_old_root_fails(self) -> None:
        tree = _tree(5)
        old_root = _tree(3).root()
        proof = tree.consistency_proof(3)
        assert verify_consistency(3, 5, old_root, tree.root(), proof) is True
        bad_old = bytes(b ^ 0xFF for b in old_root)
        assert verify_consistency(3, 5, bad_old, tree.root(), proof) is False

    def test_mutated_new_root_fails(self) -> None:
        tree = _tree(5)
        old_root = _tree(3).root()
        proof = tree.consistency_proof(3)
        bad_new = bytes(b ^ 0xFF for b in tree.root())
        assert verify_consistency(3, 5, old_root, bad_new, proof) is False

    def test_mutated_proof_element_fails(self) -> None:
        tree = _tree(6)
        old_root = _tree(4).root()
        proof = tree.consistency_proof(4)
        assert len(proof) > 0
        bad_proof = [bytes(32)] + proof[1:]
        assert verify_consistency(4, 6, old_root, tree.root(), bad_proof) is False

    def test_consistency_proof_rejects_bad_old_size(self) -> None:
        tree = _tree(5)
        with pytest.raises(ValueError):
            tree.consistency_proof(0)
        with pytest.raises(ValueError):
            tree.consistency_proof(6)
        with pytest.raises(ValueError):
            tree.consistency_proof(-1)

    def test_m1_n1_trivially_consistent(self) -> None:
        tree = _tree(1)
        root = tree.root()
        assert verify_consistency(1, 1, root, root, []) is True

    def test_consistency_single_entry_grows(self) -> None:
        for n in range(2, 8):
            old_root = _tree(1).root()
            new_tree = _tree(n)
            proof = new_tree.consistency_proof(1)
            assert verify_consistency(1, n, old_root, new_tree.root(), proof) is True
