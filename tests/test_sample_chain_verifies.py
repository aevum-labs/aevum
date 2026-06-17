# SPDX-License-Identifier: Apache-2.0
"""Guard: aevum-verify must verify the committed public sample against the
committed pinned key. If the sigchain schema changes, regenerate via
scripts/gen_sample_chain.py and commit both files together."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SAMPLE = Path("demo/public/sample-chain.json")
PUBKEY = Path("demo/public/sample-ed25519-pub.hex")


def test_public_sample_is_full_fidelity_and_synthetic() -> None:
    text = SAMPLE.read_text()
    assert '"signature"' in text, "sample must be full-fidelity (carry signatures)"
    assert '"synthetic": true' in text, "every payload must be flagged synthetic"


def test_public_sample_verifies_with_aevum_verify() -> None:
    assert SAMPLE.exists() and PUBKEY.exists()
    pub = PUBKEY.read_text().strip()
    proc = subprocess.run(
        [sys.executable, "-m", "aevum.verify", str(SAMPLE), "--ed25519-pub", pub],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"sample failed to verify; stderr: {proc.stderr}"
