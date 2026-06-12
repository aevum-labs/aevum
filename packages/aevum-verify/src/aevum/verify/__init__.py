# SPDX-License-Identifier: Apache-2.0
"""
aevum-verify — standalone independent verifier for Aevum sigchain entries.

Re-implements verification from the spec without importing aevum-core. The trust
anchor is always the pinned published key, never the key embedded in entries.

Public API:
  verify_entry(entry, *, ed25519_pub, mldsa_pub=None) -> VerifyResult
  verify_chain(entries, *, ed25519_pub, mldsa_pub=None) -> VerifyResult
  VerifyResult
  GENESIS_HASH
  DOMAIN_PREFIX
"""

from aevum.verify._core import (
    DOMAIN_PREFIX,
    GENESIS_HASH,
    VerifyResult,
    verify_chain,
    verify_entry,
)

__all__ = [
    "DOMAIN_PREFIX",
    "GENESIS_HASH",
    "VerifyResult",
    "verify_chain",
    "verify_entry",
]
