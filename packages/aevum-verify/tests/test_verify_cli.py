# SPDX-License-Identifier: Apache-2.0
"""CLI exit-code tests for aevum-verify (classical chains, no liboqs required)."""
from __future__ import annotations

import dataclasses
import subprocess
import sys
from pathlib import Path

from aevum.core.audit.sigchain import Sigchain

from aevum.verify._core import dump_chain


def _build_and_write(tmp_path: Path, n: int = 3) -> tuple[Sigchain, Path]:
    chain = Sigchain()
    events = [
        chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="test-suite")
        for i in range(n)
    ]
    chain_path = tmp_path / "chain.json"
    dump_chain(events, chain_path)
    return chain, chain_path


def test_classical_valid_exits_0(tmp_path: Path) -> None:
    """CLI exits 0 for a valid classical chain."""
    chain, chain_path = _build_and_write(tmp_path)
    proc = subprocess.run(
        [
            sys.executable, "-m", "aevum.verify",
            str(chain_path),
            "--ed25519-pub", chain._signer.public_key_bytes().hex(),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"expected exit 0; stderr: {proc.stderr}"


def test_tampered_chain_exits_1(tmp_path: Path) -> None:
    """CLI exits 1 for a tampered chain."""
    chain = Sigchain()
    events = [
        chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="test-suite")
        for i in range(2)
    ]
    tampered = list(events)
    tampered[0] = dataclasses.replace(events[0], actor="forged")

    chain_path = tmp_path / "chain.json"
    dump_chain(tampered, chain_path)

    proc = subprocess.run(
        [
            sys.executable, "-m", "aevum.verify",
            str(chain_path),
            "--ed25519-pub", chain._signer.public_key_bytes().hex(),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, f"expected exit 1; got {proc.returncode}"


def test_wrong_key_exits_1(tmp_path: Path) -> None:
    """CLI exits 1 when a wrong (different) Ed25519 key is supplied."""
    chain, chain_path = _build_and_write(tmp_path, n=1)
    wrong_chain = Sigchain()

    proc = subprocess.run(
        [
            sys.executable, "-m", "aevum.verify",
            str(chain_path),
            "--ed25519-pub", wrong_chain._signer.public_key_bytes().hex(),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, f"expected exit 1; got {proc.returncode}"


def test_missing_ed25519_pub_exits_2(tmp_path: Path) -> None:
    """CLI exits 2 (usage error) when --ed25519-pub is missing."""
    chain, chain_path = _build_and_write(tmp_path, n=1)

    proc = subprocess.run(
        [sys.executable, "-m", "aevum.verify", str(chain_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, f"expected exit 2; got {proc.returncode}"
