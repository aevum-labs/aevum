# SPDX-License-Identifier: Apache-2.0
"""Merkle tree, Signed Tree Head (STH), inclusion + consistency proofs.

RFC 6962-style Merkle tree over the append-only sigchain, using SHA3-256 (consistent
with the rest of Aevum). The base verify_chain (linear) is untouched — this is an
additive complication that reads entries and reuses the signers.

Merkle Tree Hash algorithm (RFC 6962 §2.1):
  MTH({})  = sha3_256(b"")
  MTH({d}) = leaf_hash(d) = sha3_256(0x00 || d)
  MTH(D_n) = node_hash(MTH(D[0:k]), MTH(D[k:n]))
             where k = 1 << ((n-1).bit_length()-1) = largest power of 2 < n

Leaf input: bytes.fromhex(AuditEvent.hash_event_for_chain(event))

Signed Tree Heads (STH) commit to the full log state: size + root hash + timestamp +
key metadata. STHs are hybrid-signed (Ed25519 + ML-DSA-65) using their own domain
prefix b"aevum-sth-v1\\x00" — distinct from the entry prefix b"aevum-sigchain-v1\\x00"
— providing type-level cross-domain separation: an entry signature cannot verify as
an STH signature and vice versa.

Ed25519 signs sha3_256(representative); ML-DSA-65 signs representative directly.
This mirrors the signing pattern in sigchain.new_event().

Inclusion proofs (RFC 6962 §2.1.1): PATH algorithm; verified by verify_inclusion().
Consistency proofs (RFC 6962 §2.1.2): SUBPROOF/PROOF algorithm; verified by
verify_consistency(). Both standalone verifiers are independent of MerkleTree._mth.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import time
from typing import TYPE_CHECKING, Any

from aevum.core.audit.event import AuditEvent, _canonicalize
from aevum.core.audit.signer import Signer

if TYPE_CHECKING:
    from aevum.core.signing import DualSigner

# ---------------------------------------------------------------------------
# Leaf / node domain bytes (RFC 6962 §2.1)
# ---------------------------------------------------------------------------
_LEAF: bytes = b"\x00"
_NODE: bytes = b"\x01"

# Empty-tree root: sha3_256(b"") — MTH of 0 entries per RFC 6962
EMPTY_ROOT: bytes = hashlib.sha3_256(b"").digest()

# Domain prefix for STHs — intentionally distinct from DOMAIN_PREFIX in event.py
# (b"aevum-sigchain-v1\x00") to ensure cross-type domain separation.
STH_DOMAIN: bytes = b"aevum-sth-v1\x00"


# ---------------------------------------------------------------------------
# Low-level hashing primitives
# ---------------------------------------------------------------------------

def leaf_hash(entry_digest: bytes) -> bytes:
    """sha3_256(0x00 || entry_digest) — RFC 6962 leaf hash with SHA3-256."""
    return hashlib.sha3_256(_LEAF + entry_digest).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """sha3_256(0x01 || left || right) — RFC 6962 internal node hash with SHA3-256."""
    return hashlib.sha3_256(_NODE + left + right).digest()


# ---------------------------------------------------------------------------
# Merkle Tree Hash (RFC 6962 §2.1)
# ---------------------------------------------------------------------------

class MerkleTree:
    """RFC 6962-style Merkle tree over entry digests, using SHA3-256.

    The entry digest for each AuditEvent is:
        bytes.fromhex(AuditEvent.hash_event_for_chain(event))

    MTH algorithm (RFC 6962 §2.1):
      MTH({}) = EMPTY_ROOT
      MTH({d}) = leaf_hash(d)
      MTH(D_n) = node_hash(MTH(D[0:k]), MTH(D[k:n]))
                 where k = 1 << ((n-1).bit_length()-1) = largest power of 2 < n
    """

    def __init__(self, entry_digests: list[bytes]) -> None:
        self._leaves: list[bytes] = [leaf_hash(d) for d in entry_digests]

    @property
    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        return self._mth(self._leaves)

    @staticmethod
    def _mth(nodes: list[bytes]) -> bytes:
        n = len(nodes)
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return nodes[0]
        k = 1 << ((n - 1).bit_length() - 1)  # largest power of two < n
        return node_hash(MerkleTree._mth(nodes[:k]), MerkleTree._mth(nodes[k:]))

    # ------------------------------------------------------------------
    # Inclusion proof (RFC 6962 §2.1.1)
    # ------------------------------------------------------------------

    def inclusion_proof(self, index: int) -> list[bytes]:
        """RFC 6962 §2.1.1 PATH: sibling hashes leaf→root for the entry at index."""
        if index >= self.size:
            raise ValueError(f"index {index} out of range for tree size {self.size}")
        return self._path(index, self._leaves)

    @staticmethod
    def _path(m: int, nodes: list[bytes]) -> list[bytes]:
        n = len(nodes)
        if n == 1:
            return []
        k = 1 << ((n - 1).bit_length() - 1)
        if m < k:
            return MerkleTree._path(m, nodes[:k]) + [MerkleTree._mth(nodes[k:])]
        return MerkleTree._path(m - k, nodes[k:]) + [MerkleTree._mth(nodes[:k])]

    # ------------------------------------------------------------------
    # Consistency proof (RFC 6962 §2.1.2)
    # ------------------------------------------------------------------

    def consistency_proof(self, old_size: int) -> list[bytes]:
        """RFC 6962 §2.1.2 PROOF(old_size, self.size): append-only consistency proof."""
        if old_size <= 0 or old_size > self.size:
            raise ValueError(f"old_size {old_size} out of range [1, {self.size}]")
        if old_size == self.size:
            return []
        return self._subproof(old_size, self._leaves, b=True)

    @staticmethod
    def _subproof(m: int, nodes: list[bytes], b: bool) -> list[bytes]:
        n = len(nodes)
        if m == n:
            return [] if b else [MerkleTree._mth(nodes)]
        k = 1 << ((n - 1).bit_length() - 1)
        if m <= k:
            return MerkleTree._subproof(m, nodes[:k], b) + [MerkleTree._mth(nodes[k:])]
        return MerkleTree._subproof(m - k, nodes[k:], False) + [MerkleTree._mth(nodes[:k])]


# ---------------------------------------------------------------------------
# Standalone proof verifiers — independent of MerkleTree._mth
# ---------------------------------------------------------------------------

def verify_inclusion(
    leaf_hash_value: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """RFC 6962 §2.1.1 inclusion verifier.

    Recomputes the root from leaf_hash_value + proof using only node_hash().
    Never calls MerkleTree._mth — fully independent of the tree implementation.
    Returns True iff the recomputed root matches root and index < tree_size.
    """
    if index >= tree_size:
        return False
    fn = index
    sn = tree_size - 1
    r = leaf_hash_value
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
    return r == root and sn == 0


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """RFC 6962 §2.1.2 consistency verifier (append-only / fork-detection check).

    Recomputes BOTH old_root and new_root from the proof using only node_hash().
    Never calls MerkleTree._mth — fully independent of the tree implementation.
    Returns True iff the log only grew (no history rewritten) between old and new.

    Edge cases: m==0 → True (empty tree is consistent with anything);
    m==n → True iff old_root==new_root and proof is empty; m>n → False.
    """
    if old_size > new_size:
        return False
    if old_size == 0:
        return True
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0

    fn = old_size - 1
    sn = new_size - 1

    # Advance past the shared right-chain (levels where old and new split the same way)
    while fn & 1:
        fn >>= 1
        sn >>= 1

    proof_iter = iter(proof)

    if fn == 0:
        # old_size is a power of 2: old tree is exactly a left subtree of the new tree
        fr = old_root
        sr = old_root
    else:
        first = next(proof_iter, None)
        if first is None:
            return False
        fr = first
        sr = first

    for c in proof_iter:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return False
    return fr == old_root and sr == new_root


# ---------------------------------------------------------------------------
# Signed Tree Head (STH)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class SignedTreeHead:
    """Hybrid-signed commitment to the full log state at a given tree size.

    Both signatures (Ed25519 + ML-DSA-65) are produced over the same canonical bytes:
        STH_DOMAIN + rfc8785.dumps(sth_fields)
    where tree_size and timestamp are encoded as strings to survive logs that grow
    beyond the RFC 8785 safe-integer range (2^53-1).

    Ed25519 signs sha3_256(representative); ML-DSA-65 signs representative directly.
    Both must verify for the STH to be considered intact.
    """

    tree_size: int
    root_hash: str    # hex (32 bytes = 64 chars)
    timestamp: int    # Unix seconds
    log_id: str       # Ed25519 public key hex (key_id of the primary signer)
    hash_alg: str     # always "sha3-256"
    key_scheme: str   # always "ed25519+ml-dsa-65"
    ed25519_sig: str  # url-safe base64 (no padding), Ed25519 over sha3_256(representative)
    mldsa65_sig: str  # hex, ML-DSA-65 over representative directly
    mldsa65_pub: str  # hex, ML-DSA-65 public key (1952 bytes)
    ed25519_pub: str  # hex, Ed25519 public key (32 bytes)


def _sth_fields(
    *,
    tree_size: int,
    root_hash: str,
    timestamp: int,
    log_id: str,
    hash_alg: str,
    key_scheme: str,
) -> dict[str, Any]:
    """Build the STH canonical fields dict with tree_size and timestamp as strings."""
    return {
        "hash_alg": hash_alg,
        "key_scheme": key_scheme,
        "log_id": log_id,
        "root_hash": root_hash,
        # tree_size and timestamp encoded as strings — may exceed 2^53 in long-lived logs
        "timestamp": str(timestamp),
        "tree_size": str(tree_size),
    }


def sth_representative(fields: dict[str, Any]) -> bytes:
    """STH_DOMAIN + rfc8785(fields) — the canonical bytes both STH signatures cover."""
    return STH_DOMAIN + _canonicalize(fields)


# ---------------------------------------------------------------------------
# MerkleLog — read-only over events, reuses signers from Sigchain
# ---------------------------------------------------------------------------

class MerkleLog:
    """Computes and verifies Signed Tree Heads over a list of AuditEvents.

    MerkleLog is read-only: it never mutates events, the ledger, or the sigchain.
    It reuses the signers from Sigchain to produce/verify the STH signatures.
    The base verify_chain (linear) in Sigchain is untouched — MerkleLog is an
    additive complication.

    Args:
        signer: The primary Ed25519 signer (same instance as passed to Sigchain).
        dual_signer: The ML-DSA-65 dual signer (required for STH signing).
    """

    def __init__(
        self,
        signer: Signer,
        dual_signer: DualSigner | None = None,
    ) -> None:
        self._signer = signer
        self._dual_signer = dual_signer

    def signed_tree_head(self, events: list[AuditEvent]) -> SignedTreeHead:
        """Build the Merkle tree over events and return a hybrid-signed STH.

        Entry digest per event: bytes.fromhex(AuditEvent.hash_event_for_chain(event)).
        STH fields canonicalized with STH_DOMAIN for cross-type domain separation.
        Ed25519 signs sha3_256(representative); ML-DSA-65 signs representative directly.
        ML-DSA-65 is belt-and-suspenders verified immediately after signing.

        Raises:
            RuntimeError: if dual_signer was not provided.
        """
        if self._dual_signer is None:
            raise RuntimeError(
                "MerkleLog requires a DualSigner for hybrid STH signing. "
                "Pass dual_signer= to MerkleLog()."
            )

        from aevum.core.signing import DualSigner

        digests = [bytes.fromhex(AuditEvent.hash_event_for_chain(e)) for e in events]
        tree = MerkleTree(digests)
        root = tree.root()
        ts = int(time.time())
        log_id = self._signer.key_id
        scheme = f"ed25519+{self._dual_signer.scheme_suffix}"

        fields = _sth_fields(
            tree_size=tree.size,
            root_hash=root.hex(),
            timestamp=ts,
            log_id=log_id,
            hash_alg="sha3-256",
            key_scheme=scheme,
        )
        representative = sth_representative(fields)
        digest = hashlib.sha3_256(representative).digest()

        # Ed25519 signs sha3_256(representative) — consistent with sigchain.new_event()
        ed25519_sig_bytes = self._signer.sign(digest)
        ed25519_sig = base64.urlsafe_b64encode(ed25519_sig_bytes).rstrip(b"=").decode()

        # ML-DSA-65 signs representative directly (not its hash)
        dual_sig = self._dual_signer.sign(representative)
        # Belt-and-suspenders: verify ML-DSA-65 at write time
        DualSigner.verify_mldsa(representative, dual_sig.mldsa65_sig, dual_sig.mldsa65_pub)

        return SignedTreeHead(
            tree_size=tree.size,
            root_hash=root.hex(),
            timestamp=ts,
            log_id=log_id,
            hash_alg="sha3-256",
            key_scheme=scheme,
            ed25519_sig=ed25519_sig,
            mldsa65_sig=dual_sig.mldsa65_sig.hex(),
            mldsa65_pub=dual_sig.mldsa65_pub.hex(),
            ed25519_pub=self._signer.public_key_bytes().hex(),
        )

    def verify_sth(self, sth: SignedTreeHead) -> bool:
        """Verify both signatures on a SignedTreeHead. Fail-closed — both must pass.

        Reconstructs sth_representative from the STH's fields, then verifies:
          - Ed25519 over sha3_256(representative) using sth.ed25519_pub
          - ML-DSA-65 over representative directly using sth.mldsa65_pub

        Returns False if either signature is invalid, if liboqs is absent, or on any
        unexpected verification failure. Never raises — always returns a bool.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        fields = _sth_fields(
            tree_size=sth.tree_size,
            root_hash=sth.root_hash,
            timestamp=sth.timestamp,
            log_id=sth.log_id,
            hash_alg=sth.hash_alg,
            key_scheme=sth.key_scheme,
        )
        representative = sth_representative(fields)
        digest = hashlib.sha3_256(representative).digest()

        try:
            sig_bytes = base64.urlsafe_b64decode(sth.ed25519_sig + "==")
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sth.ed25519_pub))
            pub.verify(sig_bytes, digest)
        except Exception:
            return False

        try:
            from aevum.core.signing import DualSigner
            DualSigner.verify_mldsa(
                representative,
                bytes.fromhex(sth.mldsa65_sig),
                bytes.fromhex(sth.mldsa65_pub),
            )
        except Exception:
            return False

        return True
