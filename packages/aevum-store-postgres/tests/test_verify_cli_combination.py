# SPDX-License-Identifier: Apache-2.0
"""
HO-G-PG2 — un-fakeable combination test (GREEN criterion (a)).

Pairs a real DualSigner (Ed25519 + ML-DSA-65) with a real PostgresLedger and
verifies the result with aevum-verify -- a *separate* package that shares no
code with the producer (aevum.verify._core / _format.py are reimplemented
from the public spec, not imported from aevum-core; see that module's
docstring and the AST import test in aevum-verify's own test_merkle_sth.py).

Before the HO-G-PG2 fix, PostgresLedger._row_to_event() silently dropped
key_scheme (itself a signed field) back to its dataclass default "ed25519"
and dropped mldsa65_sig/mldsa65_pub entirely. A chain fetched back from the
ledger therefore failed even the *classical* Ed25519 check once re-verified
independently -- not just ML-DSA-65. This test pins that failure mode shut
end-to-end: ledger.append() -> ledger.all_events() -> dump_chain() -> a real
`python -m aevum.verify` subprocess invocation against the pinned public
keys, with no shortcuts back into the producer's own verify_chain().
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from aevum.core.audit.sigchain import Sigchain

from aevum.store.postgres.ledger import PostgresLedger

try:
    import oqs as _oqs_check  # noqa: F401

    _DUAL_SIGNER_AVAILABLE = True
except (ImportError, OSError, SystemExit):
    _DUAL_SIGNER_AVAILABLE = False

if _DUAL_SIGNER_AVAILABLE:
    from aevum.core.signing import DualSigner

from aevum.verify._core import dump_chain
from test_ledger import FakeConn

pytestmark = pytest.mark.skipif(
    not _DUAL_SIGNER_AVAILABLE, reason="requires liboqs-python ([pqc] extra)"
)


def _run_aevum_verify(chain_path: Path, ed25519_pub_hex: str, mldsa65_pub_hex: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, "-m", "aevum.verify",
            str(chain_path),
            "--ed25519-pub", ed25519_pub_hex,
            "--mldsa65-pub", mldsa65_pub_hex,
        ],
        capture_output=True,
        text=True,
    )


class TestPostgresLedgerHybridVerifiedByIndependentCLI:
    """GREEN criterion (a): DualSigner + PostgresLedger must verify end-to-end
    through a completely independent verifier process -- not aevum-core's own
    Sigchain.verify_chain(), which a regression in the *producer* could never
    catch even in principle."""

    def test_single_hybrid_event_through_ledger_verifies_via_cli(self, tmp_path: Path) -> None:
        dual = DualSigner.generate()
        sc = Sigchain(dual_signer=dual)
        ledger = PostgresLedger(FakeConn(), sc)

        ledger.append(event_type="rt.cli.hybrid", payload={"x": 1}, actor="tester")
        fetched_events = ledger.all_events()
        assert len(fetched_events) == 1

        chain_path = tmp_path / "chain.json"
        dump_chain(fetched_events, chain_path)

        proc = _run_aevum_verify(
            chain_path,
            sc._signer.public_key_bytes().hex(),
            dual.mldsa65_public_key.hex(),
        )

        assert proc.returncode == 0, (
            f"expected VERIFIED (exit 0), got exit {proc.returncode}; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert "VERIFIED" in proc.stdout

    def test_multi_event_hybrid_chain_through_ledger_verifies_via_cli(self, tmp_path: Path) -> None:
        """Full-chain version: every prior_hash link and every per-entry
        Ed25519+ML-DSA-65 signature must survive ledger storage and be
        re-derivable by a verifier that never saw the in-memory Sigchain."""
        dual = DualSigner.generate()
        sc = Sigchain(dual_signer=dual)
        ledger = PostgresLedger(FakeConn(), sc)

        for i in range(5):
            ledger.append(event_type=f"rt.cli.hybrid.{i}", payload={"i": i}, actor="tester")
        fetched_events = ledger.all_events()
        assert len(fetched_events) == 5

        chain_path = tmp_path / "chain.json"
        dump_chain(fetched_events, chain_path)

        proc = _run_aevum_verify(
            chain_path,
            sc._signer.public_key_bytes().hex(),
            dual.mldsa65_public_key.hex(),
        )

        assert proc.returncode == 0, (
            f"expected VERIFIED (exit 0), got exit {proc.returncode}; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert "5 entries intact" in proc.stdout

    def test_ledger_restart_then_continued_chain_still_verifies_via_cli(self, tmp_path: Path) -> None:
        """Combines the two failure modes HO-G-PG2 closes: a fresh PostgresLedger
        re-attached to the same (fake) connection must resume the chain
        correctly (_resume_chain_from_db) AND every event -- pre- and
        post-restart -- must still satisfy an independent verifier."""
        dual = DualSigner.generate()
        sc1 = Sigchain(dual_signer=dual)
        conn = FakeConn()
        ledger1 = PostgresLedger(conn, sc1)
        ledger1.append(event_type="rt.cli.pre_restart", payload={"phase": 1}, actor="tester")

        # Simulate a process restart: same persisted Ed25519 key feeding a
        # fresh Sigchain/PostgresLedger pair against the same underlying rows.
        from aevum.core.audit.signer import InProcessSigner

        persisted_signer = sc1._signer
        sc2 = Sigchain(
            signer=InProcessSigner(
                private_key=persisted_signer._private_key, key_id=persisted_signer.key_id
            ),
            dual_signer=dual,
        )
        ledger2 = PostgresLedger(conn, sc2)
        ledger2.append(event_type="rt.cli.post_restart", payload={"phase": 2}, actor="tester")

        fetched_events = ledger2.all_events()
        assert len(fetched_events) == 2

        chain_path = tmp_path / "chain.json"
        dump_chain(fetched_events, chain_path)

        proc = _run_aevum_verify(
            chain_path,
            sc2._signer.public_key_bytes().hex(),
            dual.mldsa65_public_key.hex(),
        )

        assert proc.returncode == 0, (
            f"expected VERIFIED (exit 0), got exit {proc.returncode}; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert "2 entries intact" in proc.stdout

    def test_tampered_fetched_event_fails_independent_cli_verification(self, tmp_path: Path) -> None:
        """Negative control: an event tampered with *after* the lossless
        round trip must still be rejected -- proves this test exercises real
        cryptographic verification, not just a passthrough of stored bytes."""
        dual = DualSigner.generate()
        sc = Sigchain(dual_signer=dual)
        ledger = PostgresLedger(FakeConn(), sc)
        ledger.append(event_type="rt.cli.hybrid", payload={"x": 1}, actor="tester")
        fetched_events = ledger.all_events()

        chain_path = tmp_path / "chain.json"
        dump_chain(fetched_events, chain_path)
        tampered = json.loads(chain_path.read_text())
        tampered[0]["actor"] = "forged-actor"
        chain_path.write_text(json.dumps(tampered))

        proc = _run_aevum_verify(
            chain_path,
            sc._signer.public_key_bytes().hex(),
            dual.mldsa65_public_key.hex(),
        )

        assert proc.returncode == 1
        assert "FAILED" in proc.stderr
