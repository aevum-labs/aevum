# SPDX-License-Identifier: Apache-2.0
"""
CLI for aevum-verify — standalone independent sigchain verifier.

Usage:
  aevum-verify <entries.json> --ed25519-pubkey <hex|file> [--mldsa-pubkey <hex|file>]

Exit codes:
  0  VERIFIED — all entries and chain linkage intact
  1  FAILED  — signature, chain, or trust-anchor check failed
  2  usage / input error (bad arguments or unreadable file)

The trust anchor (--ed25519-pubkey / --mldsa-pubkey) must be the published key obtained
out-of-band. The verifier never trusts the key embedded in entries.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from aevum.verify._core import verify_chain


def _load_pubkey(spec: str) -> bytes:
    """Load a public key from a hex string or a file containing hex."""
    p = Path(spec)
    text = p.read_text().strip() if p.exists() else spec.strip()
    return bytes.fromhex(text)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aevum-verify",
        description=(
            "Standalone Aevum sigchain verifier. Re-implements verification from spec "
            "without trusting Aevum infrastructure. Trust anchor = pinned published key."
        ),
    )
    parser.add_argument("entries_file", help="JSON file: list of chain entry dicts")
    parser.add_argument(
        "--ed25519-pubkey",
        required=True,
        metavar="HEX_OR_FILE",
        help="Pinned Ed25519 public key: 64-char hex string or path to a file containing it",
    )
    parser.add_argument(
        "--mldsa-pubkey",
        metavar="HEX_OR_FILE",
        help="Pinned ML-DSA-65 public key: hex string or file path (required for hybrid chains)",
    )
    args = parser.parse_args()

    try:
        raw = Path(args.entries_file).read_text()
        entries: list[dict[str, Any]] = json.loads(raw)
        if not isinstance(entries, list):
            raise ValueError("entries file must contain a JSON array")
    except Exception as exc:
        print(f"Error reading entries file: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        ed25519_pub = _load_pubkey(args.ed25519_pubkey)
    except Exception as exc:
        print(f"Error loading Ed25519 public key: {exc}", file=sys.stderr)
        sys.exit(2)

    mldsa_pub: bytes | None = None
    if args.mldsa_pubkey:
        try:
            mldsa_pub = _load_pubkey(args.mldsa_pubkey)
        except Exception as exc:
            print(f"Error loading ML-DSA public key: {exc}", file=sys.stderr)
            sys.exit(2)

    result = verify_chain(entries, ed25519_pub=ed25519_pub, mldsa_pub=mldsa_pub)
    print(str(result))
    sys.exit(0 if result.ok else 1)
