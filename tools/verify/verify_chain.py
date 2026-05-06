#!/usr/bin/env python3
"""
verify_chain.py — Aevum sigchain reference verifier

Verifies the integrity of an Aevum episodic ledger export:
  - Ed25519 signature per event (see aevum-signing-v1.md)
  - SHA3-256 hash chain linkage
  - Payload hash integrity
  - HLC monotonicity

Usage:
    python verify_chain.py --events chain.json --public-key pubkey.pem
    python verify_chain.py --events chain.json --public-key pubkey.pem --verbose

Input:
    chain.json: JSON array of event dicts as returned by Engine.get_ledger_entries()
    pubkey.pem: PEM-encoded Ed25519 public key

Exit codes:
    0 — chain verified
    1 — verification failed (details printed to stderr)
    2 — usage error

No Aevum package required. Requires: cryptography >= 41.0

Export chain from Python:
    import json
    from aevum.core import Engine
    with open("chain.json", "w") as f:
        json.dump(engine.get_ledger_entries(), f, indent=2, default=str)

Export public key from Python:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub = engine._ledger._sigchain.public_key
    with open("pubkey.pem", "wb") as f:
        f.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# ── Genesis constant (sha3_256(b"aevum:genesis")) ─────────────────────────────
GENESIS_HASH = "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e"

# ── Signing field set — must match aevum-signing-v1.md exactly ────────────────
# 16 fields: all AuditEvent fields except payload, signature, and audit_id.
# sequence and episode_id ARE included (they are tamper-evident).
SIGNING_FIELDS = (
    "actor",
    "causation_id",
    "correlation_id",
    "episode_id",
    "event_id",
    "event_type",
    "payload_hash",
    "prior_hash",
    "schema_version",
    "sequence",
    "signer_key_id",
    "span_id",
    "system_time",
    "trace_id",
    "valid_from",
    "valid_to",
)


def _load_public_key(pem_path: Path):
    """Load an Ed25519 public key from a PEM file."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        print(
            "ERROR: cryptography package required. Install with: pip install cryptography",
            file=sys.stderr,
        )
        sys.exit(2)

    pem_bytes = pem_path.read_bytes()
    try:
        key = load_pem_public_key(pem_bytes)
    except Exception as exc:
        print(f"ERROR: Could not load public key from {pem_path}: {exc}", file=sys.stderr)
        sys.exit(2)
    return key


def _jcs_canonical(obj: dict[str, Any]) -> bytes:
    """
    Produce JCS-canonical (RFC 8785) JSON bytes.

    For Aevum signing fields (strings, integers, null only), Python's
    json.dumps with sort_keys is identical to RFC 8785 output.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _sha3_256_bytes(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _build_signing_object(event: dict[str, Any]) -> dict[str, Any]:
    """Extract the 16 signing fields. Missing optional fields become null."""
    return {field: event.get(field) for field in SIGNING_FIELDS}


def _hash_event_for_chain(event: dict[str, Any]) -> str:
    """
    SHA3-256 hex digest of the event's signing fields (for chain linking).

    This equals the digest used to produce the event's Ed25519 signature,
    and is stored as the prior_hash of the next event.
    """
    signing_obj = _build_signing_object(event)
    return _sha3_256_hex(_jcs_canonical(signing_obj))


def _decode_signature(sig_b64: str) -> bytes:
    """Decode base64url-without-padding signature."""
    padded = sig_b64 + "=" * (4 - len(sig_b64) % 4)
    return base64.urlsafe_b64decode(padded)


def _verify_payload_hash(event: dict[str, Any]) -> bool:
    """Verify payload_hash matches SHA3-256(JCS-canonical(payload))."""
    payload = event.get("payload", {})
    if not isinstance(payload, dict):
        return False
    expected = _sha3_256_hex(_jcs_canonical(payload))
    return expected == event.get("payload_hash", "")


def verify_chain(
    events: list[dict[str, Any]],
    public_key: Any,
    verbose: bool = False,
) -> tuple[bool, list[str]]:
    """
    Verify the complete chain.

    Returns (overall_ok, list_of_error_messages).
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(public_key, Ed25519PublicKey):
        return False, ["Public key is not an Ed25519 public key"]

    errors: list[str] = []
    sorted_events = sorted(events, key=lambda e: e.get("sequence", 0))

    if not sorted_events:
        return False, ["No events in chain"]

    first = sorted_events[0]
    if first.get("event_type") != "session.start":
        errors.append(
            f"seq={first.get('sequence')}: Expected session.start as first event, "
            f"got {first.get('event_type')!r}"
        )
    if first.get("prior_hash") != GENESIS_HASH:
        errors.append(
            f"seq={first.get('sequence')}: prior_hash is not the genesis constant"
        )

    prev_hash = GENESIS_HASH
    prev_system_time = 0
    prev_event: dict[str, Any] | None = None

    for i, event in enumerate(sorted_events):
        seq = event.get("sequence", f"?[{i}]")
        event_type = event.get("event_type", "?")
        prefix = f"seq={seq} ({event_type})"

        # ── Hash chain ────────────────────────────────────────────────────────
        actual_prior = event.get("prior_hash", "")
        if actual_prior != prev_hash:
            errors.append(
                f"{prefix}: prior_hash mismatch. "
                f"Expected {prev_hash[:16]}… got {actual_prior[:16]}…"
            )

        # ── Sequence monotonicity ─────────────────────────────────────────────
        if prev_event is not None:
            prev_seq = prev_event.get("sequence", 0)
            curr_seq = event.get("sequence", 0)
            if isinstance(prev_seq, int) and isinstance(curr_seq, int):
                if curr_seq != prev_seq + 1:
                    errors.append(
                        f"{prefix}: sequence gap — expected {prev_seq + 1}, got {curr_seq}"
                    )

        # ── HLC monotonicity ──────────────────────────────────────────────────
        curr_time = event.get("system_time", 0)
        if isinstance(curr_time, int) and curr_time < prev_system_time:
            errors.append(
                f"{prefix}: HLC regression — system_time went backward "
                f"({curr_time} < {prev_system_time})"
            )

        # ── Payload hash ──────────────────────────────────────────────────────
        if not _verify_payload_hash(event):
            errors.append(f"{prefix}: payload_hash does not match payload content")

        # ── Signature ─────────────────────────────────────────────────────────
        sig_b64 = event.get("signature", "")
        if not sig_b64:
            errors.append(f"{prefix}: signature field missing or empty")
        else:
            try:
                sig_bytes = _decode_signature(sig_b64)
                signing_obj = _build_signing_object(event)
                canonical = _jcs_canonical(signing_obj)
                digest = _sha3_256_bytes(canonical)
                public_key.verify(sig_bytes, digest)
                if verbose:
                    print(f"  {prefix}: signature OK")
            except InvalidSignature:
                errors.append(f"{prefix}: Ed25519 signature INVALID")
            except Exception as exc:
                errors.append(f"{prefix}: signature verification error — {exc}")

        # ── Advance state ─────────────────────────────────────────────────────
        prev_hash = _hash_event_for_chain(event)
        prev_system_time = curr_time if isinstance(curr_time, int) else prev_system_time
        prev_event = event

    return len(errors) == 0, errors


def extract_public_key_from_chain(events: list[dict[str, Any]]) -> bytes | None:
    """
    Attempt to extract the signing public key from session.start payload.
    Returns raw public key bytes if present, None otherwise.

    Forward-compatible: if a future Aevum version adds 'signing_public_key'
    to session.start, this function will use it automatically.
    """
    for event in events:
        if event.get("event_type") == "session.start":
            payload = event.get("payload", {})
            raw_b64 = payload.get("signing_public_key")
            if raw_b64 and isinstance(raw_b64, str):
                try:
                    return base64.b64decode(raw_b64 + "==")
                except Exception:
                    return None
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify Aevum sigchain integrity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_chain.py --events chain.json --public-key pubkey.pem
  python verify_chain.py --events chain.json --public-key pubkey.pem --verbose

Export chain from Python:
  import json
  from aevum.core import Engine
  with open("chain.json", "w") as f:
      json.dump(engine.get_ledger_entries(), f, indent=2, default=str)

Export public key from Python:
  from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
  pub = engine._ledger._sigchain.public_key
  with open("pubkey.pem", "wb") as f:
      f.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        """,
    )
    parser.add_argument(
        "--events",
        required=True,
        type=Path,
        help="JSON file containing the chain (output of Engine.get_ledger_entries())",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="PEM file containing the Ed25519 public key. If omitted, attempts to "
             "extract from session.start payload (only works if kernel writes the key there).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-event verification result",
    )
    args = parser.parse_args()

    try:
        events_raw = json.loads(args.events.read_text())
    except Exception as exc:
        print(f"ERROR: Could not load events from {args.events}: {exc}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(events_raw, list):
        print("ERROR: events file must contain a JSON array", file=sys.stderr)
        sys.exit(2)

    if args.public_key is not None:
        public_key = _load_public_key(args.public_key)
    else:
        raw_bytes = extract_public_key_from_chain(events_raw)
        if raw_bytes is None:
            print(
                "ERROR: --public-key required. No signing_public_key found in session.start payload.",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            public_key = Ed25519PublicKey.from_public_bytes(raw_bytes)
        except Exception as exc:
            print(f"ERROR: Could not load embedded public key: {exc}", file=sys.stderr)
            sys.exit(2)

    print(f"Verifying {len(events_raw)} events...", file=sys.stderr)
    ok, errors = verify_chain(events_raw, public_key, verbose=args.verbose)

    if ok:
        print(f"PASS: {len(events_raw)} events verified. Chain is intact.", file=sys.stdout)
        sys.exit(0)
    else:
        print(f"FAIL: {len(errors)} error(s) found:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
