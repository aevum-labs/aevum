# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Auditor evidence pack — the hand-to-your-auditor bundle.

An evidence pack is a self-contained directory an auditor can verify with the
standalone `aevum-verify` package ALONE — no Aevum installation, no producer
source code, no network access. It bundles the existing signed chain entries
(the exact wire shape `aevum-verify` consumes, see
aevum.verify._core.event_to_dict / load_chain) with the existing pinned public
key(s) and plain-language verification instructions. No new format, no new
crypto: this module assembles pieces that already exist and are already
independently verified (docs/spec/aevum-signing-v1.md,
docs/spec/aevum-signing-v2.md).

This module intentionally does NOT import aevum.verify. The chain.json shape
is reproduced locally (see _event_to_chain_dict) so that aevum-core never
depends on the standalone verifier package — that independence is the whole
point of the verifier existing as a separate, minimal-dependency package.
tests/test_evidence_pack_verifies.py cross-checks the shape against the real
aevum-verify CLI in the dev/test environment, exactly as
tests/test_sample_chain_verifies.py already does for scripts/gen_sample_chain.py.

Usage:
  from aevum.core.audit.evidence_pack import export_evidence_pack
  events = ledger.all_events()                       # list[AuditEvent]
  pub = kernel.signer.public_key_bytes()              # Ed25519, always present
  mldsa_pub = getattr(kernel.signer, "mldsa65_public_key", None)  # hybrid only
  export_evidence_pack(events, Path("./evidence-pack"), ed25519_pub=pub, mldsa65_pub=mldsa_pub)
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aevum.core.audit.event import AuditEvent

PACK_FORMAT = "aevum-evidence-pack-v1"


class EvidencePackError(Exception):
    """Raised when an evidence pack cannot be exported."""


def _event_to_chain_dict(event: AuditEvent) -> dict[str, Any]:
    """Serialize an AuditEvent to the exact dict shape aevum-verify consumes.

    Must stay byte-for-byte field-compatible with
    aevum.verify._core.event_to_dict (the verifier-consumed shape) — that
    parity is what tests/test_evidence_pack_verifies.py guards. receipt_cbor
    is excluded (not part of the verifier's input shape; binary, not JSON-safe).
    """
    return {
        "event_id": event.event_id,
        "episode_id": event.episode_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
        "system_time": event.system_time,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "actor": event.actor,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "payload": event.payload,
        "payload_hash": event.payload_hash,
        "prior_hash": event.prior_hash,
        "signature": event.signature,
        "signer_key_id": event.signer_key_id,
        "mldsa65_sig": event.mldsa65_sig,
        "mldsa65_pub": event.mldsa65_pub,
        "tsa_url": event.tsa_url,
        "tsa_token": event.tsa_token,
        "key_scheme": event.key_scheme,
        "sig_format_version": event.sig_format_version,
        "hash_alg": event.hash_alg,
        "principal_binding": event.principal_binding,
        "principal_commitment": event.principal_commitment,
        "principal_commitment_key_id": event.principal_commitment_key_id,
    }


def _verify_command(*, hybrid: bool) -> str:
    # --ed25519-pub takes the hex string itself (or @filepath for RAW binary)
    # — NOT a bare filename. ed25519-pub.hex holds hex *text*, so it must be
    # read into the argument value via shell command substitution.
    cmd = 'aevum-verify chain.json --ed25519-pub "$(cat ed25519-pub.hex)"'
    if hybrid:
        cmd += ' --mldsa65-pub "$(cat mldsa65-pub.hex)"'
    return cmd


def _verify_txt(*, hybrid: bool) -> str:
    command = _verify_command(hybrid=hybrid)
    key_files = "ed25519-pub.hex and mldsa65-pub.hex" if hybrid else "ed25519-pub.hex"
    install_cmd = "pip install 'aevum-verify[pqc]'" if hybrid else "pip install aevum-verify"
    pqc_note = (
        "\n   This chain is dual-signed (Ed25519 + ML-DSA-65), so the [pqc] extra\n"
        "   (liboqs) is required — plain \"aevum-verify\" cannot check the\n"
        "   post-quantum signature and will fail with \"liboqs unavailable\".\n"
        if hybrid
        else ""
    )
    return f"""Aevum Auditor Evidence Pack — Independent Verification
========================================================

This pack lets you verify the integrity of an Aevum episodic-ledger chain
using ONLY the standalone "aevum-verify" package. No Aevum installation, no
producer source code, and no network access are required.

1. Install the verifier (a clean virtual environment is fine):

     {install_cmd}
{pqc_note}
   Install "aevum-verify" — NOT "aevum-cli". The "aevum verify" subcommand
   of aevum-cli depends on aevum-core and is NOT an independent verification
   path; aevum-verify has no dependency on aevum-core or any other Aevum
   package.

2. Run, from inside this pack directory (bash, zsh, or another POSIX shell —
   the command substitution reads the pinned key out of the .hex file):

     {command}

3. Expected output:

   PASS — chain is intact:
     VERIFIED — N entries intact
     (exit code 0)

   FAIL — chain is tampered, forged, or truncated:
     FAILED — entry <N>: <reason>
     (exit code 1)

   A FAIL names the first failing entry and the specific check that failed
   (for example "payload_hash mismatch", "Ed25519 signature invalid", or
   "prior_hash mismatch"). Any FAIL means this pack's contents must not be
   trusted.

Pack contents:
  chain.json     — the signed episodic-ledger entries (verifier input)
  {key_files} — pinned public key(s), out-of-band trust anchor
  manifest.json  — pack metadata (chain id, entry count, key id, created-at)
  VERIFY.txt     — this file
"""


def export_evidence_pack(
    events: Sequence[AuditEvent],
    out_dir: Path,
    *,
    ed25519_pub: bytes,
    mldsa65_pub: bytes | None = None,
) -> Path:
    """Export a self-contained auditor evidence pack to out_dir.

    Args:
        events: The full-fidelity signed chain segment to hand to an auditor,
            in chain order starting from genesis (e.g. InMemoryLedger.all_events(),
            or a slice of it). Must be non-empty.
        out_dir: Directory to write the pack into. Created if absent.
        ed25519_pub: The pinned Ed25519 public key bytes for this chain (32
            bytes) — the sole classical trust anchor, supplied out-of-band
            exactly as aevum-verify's --ed25519-pub expects.
        mldsa65_pub: The pinned ML-DSA-65 public key bytes, required only for
            hybrid (ed25519+ml-dsa-65) chains.

    Returns:
        out_dir, populated with chain.json, ed25519-pub.hex, manifest.json,
        VERIFY.txt, and (for hybrid chains) mldsa65-pub.hex.

    Raises:
        EvidencePackError: if events is empty.
    """
    if not events:
        raise EvidencePackError("cannot export an evidence pack from an empty chain")

    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "chain.json").write_text(
        json.dumps([_event_to_chain_dict(e) for e in events], indent=2)
    )

    (out_dir / "ed25519-pub.hex").write_text(ed25519_pub.hex() + "\n")

    hybrid = mldsa65_pub is not None
    if hybrid:
        assert mldsa65_pub is not None  # narrowed for type checkers
        (out_dir / "mldsa65-pub.hex").write_text(mldsa65_pub.hex() + "\n")

    last = events[-1]
    manifest = {
        "format": PACK_FORMAT,
        "chain_id": AuditEvent.hash_event_for_chain(last),
        "entry_count": len(events),
        "key_id": last.signer_key_id,
        "key_scheme": last.key_scheme,
        "created_at": datetime.now(UTC).isoformat(),
        "verifier_package": "aevum-verify",
        "verify_command": _verify_command(hybrid=hybrid),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    (out_dir / "VERIFY.txt").write_text(_verify_txt(hybrid=hybrid))

    return out_dir
