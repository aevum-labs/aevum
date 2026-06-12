# SPDX-License-Identifier: Apache-2.0
"""
aevum-verify — standalone sigchain verifier CLI.

Usage:
  aevum-verify CHAIN_FILE --ed25519-pub HEX [--mldsa65-pub HEX]

  CHAIN_FILE     Path to a JSON file containing a list of serialised chain entries.
  --ed25519-pub  Pinned Ed25519 public key as 64-char hex, or @/path/to/file for
                 raw 32-byte binary.
  --mldsa65-pub  Pinned ML-DSA-65 public key as hex or @filepath; required for
                 hybrid (ed25519+ml-dsa-65) chains.

Exit codes:
  0  VERIFIED — all entries intact.
  1  FAILED   — chain tampered, signature invalid, or trust-anchor mismatch.
  2  Usage error (bad arguments or unreadable file).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aevum.verify._core import load_chain, verify_chain


def _load_key(value: str) -> bytes:
    """Load a key from a hex string or @filepath (raw binary)."""
    if value.startswith("@"):
        return Path(value[1:]).read_bytes()
    return bytes.fromhex(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aevum-verify",
        description="Verify an Aevum sigchain export against pinned public keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("chain_file", metavar="CHAIN_FILE", help="path to JSON chain file")
    parser.add_argument(
        "--ed25519-pub",
        required=True,
        metavar="HEX",
        help="pinned Ed25519 public key (64-char hex or @filepath)",
    )
    parser.add_argument(
        "--mldsa65-pub",
        default=None,
        metavar="HEX",
        help="pinned ML-DSA-65 public key (hex or @filepath); required for hybrid chains",
    )
    args = parser.parse_args()

    try:
        ed25519_pub = _load_key(args.ed25519_pub)
    except Exception as exc:
        print(f"ERROR: invalid --ed25519-pub: {exc}", file=sys.stderr)
        sys.exit(2)

    mldsa65_pub: bytes | None = None
    if args.mldsa65_pub:
        try:
            mldsa65_pub = _load_key(args.mldsa65_pub)
        except Exception as exc:
            print(f"ERROR: invalid --mldsa65-pub: {exc}", file=sys.stderr)
            sys.exit(2)

    try:
        chain_path = Path(args.chain_file)
        entries = load_chain(chain_path)
    except Exception as exc:
        print(f"ERROR: could not load chain file: {exc}", file=sys.stderr)
        sys.exit(2)

    result = verify_chain(entries, ed25519_pub=ed25519_pub, mldsa65_pub=mldsa65_pub)

    if result.ok:
        print(f"VERIFIED — {len(entries)} entries intact")
        sys.exit(0)
    else:
        idx = result.failing_index
        reason = result.reason
        if idx is not None:
            print(f"FAILED — entry {idx}: {reason}", file=sys.stderr)
        else:
            print(f"FAILED — {reason}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
