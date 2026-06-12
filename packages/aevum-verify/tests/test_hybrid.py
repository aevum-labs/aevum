# SPDX-License-Identifier: Apache-2.0
"""Hybrid (Ed25519 + ML-DSA-65) chain verification tests — requires liboqs.

These 11 tests MUST RUN (not skip) when liboqs 0.14.0 is installed.

The conformance cross-checks (test_hybrid_both_agree_verified and
test_hybrid_tamper_both_agree_failed_at_same_index) guard against the class of
bug fixed in P2j: a fabricated trust check that passes classical chains (skipped
in CI without liboqs) but always fails hybrid ones.
"""
from __future__ import annotations

import dataclasses

import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, SystemExit):
    pytest.skip(
        "liboqs native library not available — skipping hybrid verification tests",
        allow_module_level=True,
    )

from aevum.core.audit.sigchain import Sigchain
from aevum.core.signing import DualSigner

from aevum.verify._core import verify_chain


def _hybrid_chain(n: int = 3) -> tuple[Sigchain, DualSigner, list]:
    ds = DualSigner.generate()
    chain = Sigchain(dual_signer=ds)
    events = [
        chain.new_event(event_type=f"h.{i}", payload={"i": i}, actor="test-suite")
        for i in range(n)
    ]
    return chain, ds, events


class TestHybridValid:
    def test_hybrid_valid_chain_verified(self) -> None:
        chain, ds, events = _hybrid_chain(3)
        result = verify_chain(
            events,
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is True

    def test_hybrid_both_agree_verified(self) -> None:
        """Conformance cross-check: aevum-core and aevum-verify both report VERIFIED."""
        chain, ds, events = _hybrid_chain(3)

        # aevum-core reference implementation
        core_ok = chain.verify_chain(events)

        # aevum-verify (this package)
        av_result = verify_chain(
            events,
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )

        assert core_ok is True, "aevum-core must report the chain as verified"
        assert av_result.ok is True, "aevum-verify must report the chain as verified"

    def test_hybrid_tamper_both_agree_failed_at_same_index(self) -> None:
        """Conformance cross-check: both verifiers fail at the same entry after tamper."""
        chain, ds, events = _hybrid_chain(5)
        tamper_index = 2
        tampered_events = list(events)
        # actor is a signed field — mutating it breaks the signature
        tampered_events[tamper_index] = dataclasses.replace(
            events[tamper_index], actor="forged-actor"
        )

        # aevum-core: full tampered chain fails; prefix before tamper passes
        assert chain.verify_chain(tampered_events) is False
        assert chain.verify_chain(events[:tamper_index]) is True

        # aevum-verify: same failure at the same index
        av_full = verify_chain(
            tampered_events,
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        av_prefix = verify_chain(
            events[:tamper_index],
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )

        assert av_full.ok is False, "aevum-verify must fail on the tampered chain"
        assert av_full.failing_index == tamper_index, (
            f"expected failing_index={tamper_index}, got {av_full.failing_index}"
        )
        assert av_prefix.ok is True, "prefix before the tampered entry must pass"


class TestHybridTrustAnchor:
    def test_forged_mldsa65_pub_fails(self) -> None:
        """Trust-anchor test: embedded mldsa65_pub != pinned key → FAIL."""
        chain, ds, events = _hybrid_chain(1)
        ds_other = DualSigner.generate()
        # Embed a different ML-DSA public key while keeping the original ML-DSA signature.
        # The embedded key does not match the pinned anchor → fail closed.
        tampered = dataclasses.replace(
            events[0], mldsa65_pub=ds_other.mldsa65_public_key.hex()
        )
        result = verify_chain(
            [tampered],
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False

    def test_hybrid_no_pinned_mldsa_key_fails(self) -> None:
        """Hybrid entry without a pinned ML-DSA key → FAIL (caller must supply it)."""
        chain, ds, events = _hybrid_chain(1)
        result = verify_chain(
            events,
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=None,  # deliberately omitted
        )
        assert result.ok is False


class TestHybridDowngradeDefense:
    def test_hybrid_missing_mldsa65_sig_fails(self) -> None:
        """Stripped ML-DSA signature in a hybrid entry → FAIL (downgrade/tamper)."""
        chain, ds, events = _hybrid_chain(1)
        tampered = dataclasses.replace(events[0], mldsa65_sig=None)
        result = verify_chain(
            [tampered],
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False

    def test_hybrid_missing_mldsa65_pub_fails(self) -> None:
        """Stripped embedded ML-DSA pub in a hybrid entry → FAIL."""
        chain, ds, events = _hybrid_chain(1)
        tampered = dataclasses.replace(events[0], mldsa65_pub=None)
        result = verify_chain(
            [tampered],
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False

    def test_hybrid_tamper_mldsa65_sig_fails(self) -> None:
        """Corrupted ML-DSA signature → FAIL."""
        chain, ds, events = _hybrid_chain(1)
        assert events[0].mldsa65_sig is not None
        bad_sig = bytes.fromhex(events[0].mldsa65_sig)
        bad_sig = bad_sig[:-1] + bytes([bad_sig[-1] ^ 0xFF])
        tampered = dataclasses.replace(events[0], mldsa65_sig=bad_sig.hex())
        result = verify_chain(
            [tampered],
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False

    def test_hybrid_unknown_scheme_level_fails(self) -> None:
        """Unknown ML-DSA level suffix → FAIL (fail closed, no warn-and-fallback)."""
        chain, ds, events = _hybrid_chain(1)
        tampered = dataclasses.replace(events[0], key_scheme="ed25519+ml-dsa-999")
        result = verify_chain(
            [tampered],
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False

    def test_hybrid_homogeneity_fails(self) -> None:
        """Mixed classical + hybrid entries in one chain → FAIL (splice attack)."""
        classical_chain = Sigchain()
        classical_event = classical_chain.new_event(
            event_type="t.classical", payload={"x": 1}, actor="test-suite"
        )

        chain, ds, events = _hybrid_chain(1)
        mixed = [classical_event, events[0]]
        result = verify_chain(
            mixed,
            ed25519_pub=chain._signer.public_key_bytes(),
            mldsa65_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False


class TestHybridCLI:
    def test_hybrid_valid_exits_0(self, tmp_path: object) -> None:
        """CLI exits 0 for a valid hybrid chain."""
        import subprocess
        import sys
        from pathlib import Path

        from aevum.verify._core import dump_chain

        chain, ds, events = _hybrid_chain(2)

        chain_path = Path(str(tmp_path)) / "chain.json"
        dump_chain(events, chain_path)

        proc = subprocess.run(
            [
                sys.executable, "-m", "aevum.verify",
                str(chain_path),
                "--ed25519-pub", chain._signer.public_key_bytes().hex(),
                "--mldsa65-pub", ds.mldsa65_public_key.hex(),
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"expected exit 0, got {proc.returncode}; stderr: {proc.stderr}"
        )
