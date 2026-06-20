# SPDX-License-Identifier: Apache-2.0
"""Guard: aevum-verify must verify the committed public v2 (principal-binding)
sample against the committed pinned key. If the sigchain schema changes,
regenerate via scripts/gen_sample_chain_v2.py and commit both files together."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SAMPLE = Path("demo/public/sample-chain-v2.json")
PUBKEY = Path("demo/public/sample-chain-v2-pub.hex")


def test_public_sample_is_full_fidelity_and_synthetic() -> None:
    text = SAMPLE.read_text()
    assert '"signature"' in text, "sample must be full-fidelity (carry signatures)"
    assert '"synthetic": true' in text, "every payload must be flagged synthetic"


def test_public_sample_never_carries_a_raw_subject_or_bearer_token() -> None:
    """DD7: the raw bound credential identity and bare 'sub' must never appear
    in the file, regardless of what the generator script passed in."""
    text = SAMPLE.read_text()
    assert '"sub"' not in text
    assert "DEMO-0001-synthetic" not in text or '"principal_identity"' not in text


def test_public_sample_spans_v1_then_v2() -> None:
    """DD4: demonstrates the documented mixed-version chain (per-entry dispatch)."""
    entries = json.loads(SAMPLE.read_text())
    versions = [e["sig_format_version"] for e in entries]
    assert versions[0] == 1
    assert versions[-1] == 2
    assert versions == sorted(versions), "sig_format_version must never decrease (DD4)"
    assert 2 in versions


def test_public_sample_verifies_with_aevum_verify() -> None:
    assert SAMPLE.exists() and PUBKEY.exists()
    pub = PUBKEY.read_text().strip()
    proc = subprocess.run(
        [sys.executable, "-m", "aevum.verify", str(SAMPLE), "--ed25519-pub", pub],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"sample failed to verify; stderr: {proc.stderr}"
