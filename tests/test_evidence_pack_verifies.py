# SPDX-License-Identifier: Apache-2.0
"""Guard: aevum.core.audit.evidence_pack.export_evidence_pack produces a pack
that the standalone aevum-verify CLI verifies on its own — and rejects when
tampered. This is the same cold-path contract test_sample_chain_verifies.py
runs for the committed public sample, applied to the exporter itself."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

from aevum.core.audit.evidence_pack import export_evidence_pack
from aevum.core.audit.sigchain import Sigchain
from aevum.verify._core import event_to_dict, load_chain

if TYPE_CHECKING:
    from pathlib import Path


def _build_pack(tmp_path: Path) -> Path:
    chain = Sigchain()
    events = [
        chain.new_event(
            event_type="consent.granted",
            payload={"subject": "DEMO-0001", "synthetic": True},
            actor="test-suite",
        ),
        chain.new_event(
            event_type="agent.tool_call",
            payload={"tool": "ledger.read", "synthetic": True},
            actor="test-suite",
        ),
    ]
    return export_evidence_pack(
        events, tmp_path / "pack", ed25519_pub=chain._signer.public_key_bytes()
    )


def _run_verify(pack: Path) -> subprocess.CompletedProcess[str]:
    pub = (pack / "ed25519-pub.hex").read_text().strip()
    return subprocess.run(
        [sys.executable, "-m", "aevum.verify", str(pack / "chain.json"), "--ed25519-pub", pub],
        capture_output=True,
        text=True,
    )


def test_evidence_pack_chain_json_matches_verifier_input_shape(tmp_path: Path) -> None:
    """The exporter reimplements aevum.verify._core.event_to_dict locally
    (aevum-core must not import aevum.verify); this guards that the two stay
    field-for-field identical."""
    pack = _build_pack(tmp_path)
    entries = json.loads((pack / "chain.json").read_text())
    verify_events = load_chain(pack / "chain.json")
    for entry, verify_event in zip(entries, verify_events, strict=True):
        assert entry == event_to_dict(verify_event)


def test_evidence_pack_verifies_with_standalone_aevum_verify(tmp_path: Path) -> None:
    pack = _build_pack(tmp_path)
    proc = _run_verify(pack)
    assert proc.returncode == 0, f"pack failed to verify; stderr: {proc.stderr}"
    assert "VERIFIED" in proc.stdout


def test_evidence_pack_verify_txt_command_works_copy_pasted(tmp_path: Path) -> None:
    """The exact command in VERIFY.txt, run via a real shell, must succeed —
    this is what an auditor actually copy-pastes. Regression guard for the
    bug caught in cold-path testing: --ed25519-pub takes the hex *value*, not
    a bare filename, so the command must use $(cat ...) substitution."""
    pack = _build_pack(tmp_path)
    text = (pack / "VERIFY.txt").read_text()
    command_line = next(
        line.strip() for line in text.splitlines() if line.strip().startswith("aevum-verify ")
    )
    shell_command = command_line.replace("aevum-verify", f"{sys.executable} -m aevum.verify", 1)
    proc = subprocess.run(shell_command, shell=True, cwd=pack, capture_output=True, text=True)
    assert proc.returncode == 0, f"VERIFY.txt command failed; stderr: {proc.stderr}"
    assert "VERIFIED" in proc.stdout


def test_tampered_evidence_pack_is_rejected_with_entry_and_reason(tmp_path: Path) -> None:
    pack = _build_pack(tmp_path)
    chain_path = pack / "chain.json"
    entries = json.loads(chain_path.read_text())
    entries[0]["payload"]["subject"] = "TAMPERED"
    chain_path.write_text(json.dumps(entries, indent=2))

    proc = _run_verify(pack)
    assert proc.returncode == 1
    assert "entry 0" in proc.stderr
    assert "payload_hash mismatch" in proc.stderr


def test_untampered_evidence_pack_still_passes_after_tamper_check(tmp_path: Path) -> None:
    """Sanity: building a second, untouched pack still verifies (the tamper
    test above must not be passing because of a broken baseline)."""
    pack = _build_pack(tmp_path)
    proc = _run_verify(pack)
    assert proc.returncode == 0
