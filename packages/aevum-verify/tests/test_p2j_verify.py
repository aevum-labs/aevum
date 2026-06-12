# SPDX-License-Identifier: Apache-2.0
"""P2j gate tests — standalone independent sigchain verifier.

Test inventory:
  Classical chain — VERIFIED
  Hybrid chain WITH liboqs — VERIFIED (not skipped)
  Tamper: signed field → FAIL
  Tamper: prior_hash → FAIL
  Tamper: reorder entries → FAIL
  Tamper: drop entry → FAIL
  TRUST ANCHOR: forged mldsa65_pub + valid sig under it → FAIL (≠ pinned key)
  TRUST ANCHOR: wrong signer_key_id → FAIL
  TRUST ANCHOR: wrong Ed25519 key → FAIL
  Fail-closed: hybrid entry missing mldsa65_sig → FAIL
  Homogeneity: mixed-scheme chain → FAIL
  Posture attestation: chain with classical-only posture entry verifies
  CONFORMANCE CROSS-CHECK: standalone agrees with aevum-core on valid + same-index tamper
  Independence: no import of aevum.core.audit.sigchain
  CLI smoke: valid → exit 0; tampered → exit 1
"""
from __future__ import annotations

import ast
import copy
import dataclasses
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ── liboqs availability ───────────────────────────────────────────────────────

try:
    import oqs  # type: ignore[import]  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_classical_chain(n: int = 3) -> tuple[Any, list[dict[str, Any]]]:
    """Build a classical (Ed25519-only) chain of n entries. Returns (sigchain, list[dict]).

    Uses a stable key_id = pubkey.hex() (production convention from Kernel.local() /
    _PrimarySignerAdapter) so the standalone verifier's signer_key_id trust-anchor check passes.
    """
    from aevum.core.audit.sigchain import Sigchain
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    chain = Sigchain(private_key=sk, key_id=pub.hex())
    events = [
        chain.new_event(event_type=f"test.classical.{i}", payload={"i": i}, actor="test-actor")
        for i in range(n)
    ]
    dicts = [dataclasses.asdict(e) for e in events]
    return chain, dicts


def _chain_ed25519_pub(chain: Any) -> bytes:
    """Extract the raw Ed25519 public key bytes from a Sigchain."""
    return chain._signer.public_key_bytes()


def _no_liboqs_ctx() -> Any:
    """Context manager: make signing module believe liboqs is absent."""
    return patch.multiple("aevum.core.signing", _OQS_AVAILABLE=False, _oqs_module=None)


# ── Classical chain verification ──────────────────────────────────────────────

class TestClassicalChainVerification:
    def test_valid_classical_chain_verifies(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(4)
        result = verify_chain(entries, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is True
        assert result.verified_count == 4
        assert "VERIFIED" in str(result)

    def test_empty_chain_verifies(self) -> None:
        from aevum.core.audit.sigchain import Sigchain

        from aevum.verify import verify_chain
        chain = Sigchain()
        result = verify_chain([], ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is True
        assert result.verified_count == 0

    def test_single_entry_verifies(self) -> None:
        from aevum.verify import verify_chain, verify_entry
        chain, entries = _make_classical_chain(1)
        pub = _chain_ed25519_pub(chain)
        assert verify_chain(entries, ed25519_pub=pub).ok is True
        assert verify_entry(entries[0], ed25519_pub=pub).ok is True

    def test_verify_entry_result_string(self) -> None:
        from aevum.verify import verify_entry
        chain, entries = _make_classical_chain(1)
        result = verify_entry(entries[0], ed25519_pub=_chain_ed25519_pub(chain))
        assert str(result) == "VERIFIED (1 entry)"

    def test_verify_chain_result_string(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(3)
        result = verify_chain(entries, ed25519_pub=_chain_ed25519_pub(chain))
        assert str(result) == "VERIFIED (3 entries)"


# ── Hybrid chain verification WITH liboqs ────────────────────────────────────

class TestHybridChainVerification:
    @needs_liboqs
    def test_valid_hybrid_chain_verifies(self) -> None:
        """Hybrid chain verifies WITH liboqs — this test must PASS, not be skipped."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        events = [
            chain.new_event(event_type=f"test.hybrid.{i}", payload={"i": i}, actor="test")
            for i in range(3)
        ]
        dicts = [dataclasses.asdict(e) for e in events]
        assert all(d["key_scheme"] == "ed25519+ml-dsa-65" for d in dicts)
        assert all(d["mldsa65_sig"] is not None for d in dicts)

        result = verify_chain(
            dicts,
            ed25519_pub=ds.ed25519_public_key,
            mldsa_pub=ds.mldsa65_public_key,
        )
        assert result.ok is True
        assert result.verified_count == 3

    @needs_liboqs
    def test_hybrid_verify_entry(self) -> None:
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_entry

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="test.hybrid.entry", payload={}, actor="test")
        d = dataclasses.asdict(event)
        result = verify_entry(d, ed25519_pub=ds.ed25519_public_key, mldsa_pub=ds.mldsa65_public_key)
        assert result.ok is True


# ── Tamper detection ──────────────────────────────────────────────────────────

class TestTamperDetection:
    def test_tamper_signed_field_event_type(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(3)
        tampered = copy.deepcopy(entries)
        tampered[1]["event_type"] = "FORGED_EVENT_TYPE"
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 1

    def test_tamper_signed_field_payload_hash(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(3)
        tampered = copy.deepcopy(entries)
        tampered[0]["payload_hash"] = "deadbeef" * 8
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 0

    def test_tamper_signed_field_actor(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(2)
        tampered = copy.deepcopy(entries)
        tampered[0]["actor"] = "forged-actor"
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 0

    def test_tamper_signed_field_hash_alg(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(2)
        tampered = copy.deepcopy(entries)
        tampered[0]["hash_alg"] = "sha2-256"
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 0

    def test_tamper_prior_hash_middle_entry(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(4)
        tampered = copy.deepcopy(entries)
        tampered[2]["prior_hash"] = "0" * 64  # wrong prior_hash
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 2

    def test_tamper_reorder_entries(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(3)
        reordered = copy.deepcopy(entries)
        reordered[0], reordered[1] = reordered[1], reordered[0]  # swap first two
        result = verify_chain(reordered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False

    def test_tamper_drop_middle_entry(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(4)
        dropped = copy.deepcopy(entries)
        del dropped[1]  # remove middle entry → chain break
        result = verify_chain(dropped, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False

    def test_tamper_payload_contents(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(2)
        tampered = copy.deepcopy(entries)
        tampered[0]["payload"]["injected"] = "evil"  # payload hash won't match
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 0


# ── TRUST ANCHOR tests — the critical correctness proofs ─────────────────────

class TestTrustAnchor:
    @needs_liboqs
    def test_forged_mldsa65_pub_fails(self) -> None:
        """Entry carrying a different mldsa65_pub than the pinned key → FAIL.

        This is the circular-key attack: an adversary generates their own ML-DSA keypair,
        signs a forged entry with it, and embeds their public key. A naive verifier that
        checks 'does the sig verify under the key in the entry?' would accept it. The correct
        verifier checks the entry key EQUALS the pinned key and fails immediately.
        """
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain

        # Legitimate signer
        ds_legit = DualSigner.generate()
        chain = Sigchain(dual_signer=ds_legit)
        event = chain.new_event(event_type="test.forged_pub", payload={}, actor="test")
        entry = dataclasses.asdict(event)

        # Adversary's own ML-DSA keypair
        ds_forged = DualSigner.generate()
        # Forge: replace mldsa65_pub with adversary's key (and their sig over the same rep)
        # NOTE: even if we leave the original sig, the mldsa65_pub check fires first.
        forged_entry = copy.deepcopy(entry)
        forged_entry["mldsa65_pub"] = ds_forged.mldsa65_public_key.hex()

        result = verify_chain(
            [forged_entry],
            ed25519_pub=ds_legit.ed25519_public_key,
            mldsa_pub=ds_legit.mldsa65_public_key,  # pinned = legitimate key
        )
        assert result.ok is False
        assert result.failed_index == 0
        assert "pinned" in (result.failed_reason or "").lower() or "mismatch" in (result.failed_reason or "").lower()

    def test_wrong_signer_key_id_fails(self) -> None:
        """Entry with signer_key_id that doesn't match the pinned Ed25519 key → FAIL."""
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(2)
        tampered = copy.deepcopy(entries)
        tampered[0]["signer_key_id"] = "a" * 64  # wrong key id
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 0
        assert "signer_key_id" in (result.failed_reason or "")

    def test_wrong_ed25519_key_fails(self) -> None:
        """Verifying against a different Ed25519 key → FAIL (signer_key_id mismatch + invalid sig)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from aevum.verify import verify_chain

        chain_a, entries_a = _make_classical_chain(2)
        # Different key entirely (different pub bytes AND different key_id)
        sk_b = Ed25519PrivateKey.generate()
        wrong_pub = sk_b.public_key().public_bytes_raw()

        result = verify_chain(entries_a, ed25519_pub=wrong_pub)
        assert result.ok is False

    @needs_liboqs
    def test_hybrid_missing_mldsa_pub_arg_fails(self) -> None:
        """Hybrid entries require --mldsa-pubkey. Missing it → FAIL (fail-closed)."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="test.hybrid.nopub", payload={}, actor="test")
        entry = dataclasses.asdict(event)

        result = verify_chain([entry], ed25519_pub=ds.ed25519_public_key, mldsa_pub=None)
        assert result.ok is False
        assert "hybrid" in (result.failed_reason or "").lower() or "mldsa" in (result.failed_reason or "").lower()


# ── Fail-closed tests ─────────────────────────────────────────────────────────

class TestFailClosed:
    @needs_liboqs
    def test_hybrid_entry_missing_mldsa65_sig_fails(self) -> None:
        """Hybrid entry (key_scheme=ed25519+ml-dsa-65) with mldsa65_sig=None → FAIL."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="test.fail_closed", payload={}, actor="test")
        entry = dataclasses.asdict(event)

        # Strip the ML-DSA sig — simulates tamper/downgrade
        stripped = copy.deepcopy(entry)
        stripped["mldsa65_sig"] = None

        result = verify_chain(
            [stripped],
            ed25519_pub=ds.ed25519_public_key,
            mldsa_pub=ds.mldsa65_public_key,
        )
        assert result.ok is False
        assert "missing" in (result.failed_reason or "").lower() or "fail" in (result.failed_reason or "").lower()

    @needs_liboqs
    def test_hybrid_entry_missing_mldsa65_pub_fails(self) -> None:
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="test.fail_closed.pub", payload={}, actor="test")
        entry = dataclasses.asdict(event)
        stripped = copy.deepcopy(entry)
        stripped["mldsa65_pub"] = None
        result = verify_chain([stripped], ed25519_pub=ds.ed25519_public_key, mldsa_pub=ds.mldsa65_public_key)
        assert result.ok is False

    def test_sig_format_version_none_fails(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(2)
        bad = copy.deepcopy(entries)
        bad[0]["sig_format_version"] = None
        result = verify_chain(bad, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False
        assert result.failed_index == 0

    def test_sig_format_version_2_fails(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(1)
        bad = copy.deepcopy(entries)
        bad[0]["sig_format_version"] = 2
        result = verify_chain(bad, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False

    def test_unknown_key_scheme_fails(self) -> None:
        from aevum.verify import verify_chain
        chain, entries = _make_classical_chain(1)
        tampered = copy.deepcopy(entries)
        tampered[0]["key_scheme"] = "ed25519+ml-dsa-999"
        result = verify_chain(tampered, ed25519_pub=_chain_ed25519_pub(chain))
        assert result.ok is False


# ── Homogeneity ───────────────────────────────────────────────────────────────

class TestHomogeneity:
    @needs_liboqs
    def test_mixed_scheme_chain_fails(self) -> None:
        """A chain mixing classical and hybrid entries → FAIL (downgrade/splice attack)."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain

        # Classical entry
        chain_c = Sigchain()
        ev_classical = chain_c.new_event(event_type="test.classical", payload={}, actor="test")
        d_classical = dataclasses.asdict(ev_classical)

        # Hybrid entry
        ds = DualSigner.generate()
        chain_h = Sigchain(dual_signer=ds)
        ev_hybrid = chain_h.new_event(event_type="test.hybrid", payload={}, actor="test")
        d_hybrid = dataclasses.asdict(ev_hybrid)

        # Mix them — homogeneity check must reject before per-entry verification
        mixed = [d_classical, d_hybrid]
        result = verify_chain(mixed, ed25519_pub=_chain_ed25519_pub(chain_c))
        assert result.ok is False
        assert "mixed" in (result.failed_reason or "").lower() or "homogenei" in (result.failed_reason or "").lower()


# ── Posture attestation ───────────────────────────────────────────────────────

class TestPostureAttestation:
    def test_classical_chain_with_posture_attestation_verifies(self) -> None:
        """A chain starting with posture.attestation (classical-only) verifies correctly."""
        from aevum.core.audit.sigchain import Sigchain
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from aevum.verify import verify_chain

        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw()
        chain = Sigchain(private_key=sk, key_id=pub.hex())

        # Manually emit posture.attestation as first entry (seq=1)
        ev_posture = chain.new_event(
            event_type="posture.attestation",
            payload={
                "signing_posture": "classical-only",
                "scheme": "ed25519",
                "post_quantum": False,
                "reason": "explicit operator opt-in via AEVUM_SIGNING_POSTURE=classical-only",
                "note": "Ed25519-only — no ML-DSA-65 / no post-quantum protection on this chain.",
            },
            actor="aevum-core",
        )
        ev_session = chain.new_event(
            event_type="session.start",
            payload={"capture_surface": {"llm": False, "mcp": False}, "key_provenance": "external"},
            actor="aevum-core",
        )
        ev_event = chain.new_event(event_type="test.event", payload={"data": "value"}, actor="user")

        entries = [dataclasses.asdict(ev_posture), dataclasses.asdict(ev_session), dataclasses.asdict(ev_event)]

        result = verify_chain(entries, ed25519_pub=pub)
        assert result.ok is True
        assert result.verified_count == 3
        assert entries[0]["event_type"] == "posture.attestation"
        assert entries[0]["key_scheme"] == "ed25519"
        assert entries[0]["mldsa65_sig"] is None


# ── CONFORMANCE CROSS-CHECK ───────────────────────────────────────────────────

class TestConformanceCrossCheck:
    """The drift guard: standalone verifier and aevum-core verify_chain must agree."""

    def test_valid_chain_both_agree_verified(self) -> None:
        """On a valid chain, both aevum-core and standalone report VERIFIED."""
        from aevum.core.audit.sigchain import Sigchain
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from aevum.verify import verify_chain as standalone_verify

        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw()
        chain = Sigchain(private_key=sk, key_id=pub.hex())
        events = [
            chain.new_event(event_type=f"conformance.valid.{i}", payload={"i": i}, actor="test")
            for i in range(5)
        ]

        core_result = chain.verify_chain(events)
        entries = [dataclasses.asdict(e) for e in events]
        standalone_result = standalone_verify(entries, ed25519_pub=pub)

        assert core_result is True
        assert standalone_result.ok is True

    def test_tamper_both_agree_failed_at_same_index(self) -> None:
        """On a tampered chain, both fail; standalone reports the same index as tamper point."""
        from aevum.core.audit.sigchain import Sigchain
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from aevum.verify import verify_chain as standalone_verify

        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw()
        chain = Sigchain(private_key=sk, key_id=pub.hex())
        events = [
            chain.new_event(event_type=f"conformance.tamper.{i}", payload={"i": i}, actor="test")
            for i in range(5)
        ]

        TAMPER_IDX = 2
        entries = [dataclasses.asdict(e) for e in events]

        # Tamper at index 2 — mutate a signed field in the dict
        tampered_entries = copy.deepcopy(entries)
        tampered_entries[TAMPER_IDX]["event_type"] = "TAMPERED"

        # For aevum-core: rebuild AuditEvent objects with the tamper
        tampered_events = list(events)
        tampered_events[TAMPER_IDX] = dataclasses.replace(events[TAMPER_IDX], event_type="TAMPERED")

        core_result = chain.verify_chain(tampered_events)
        standalone_result = standalone_verify(tampered_entries, ed25519_pub=pub)

        assert core_result is False
        assert standalone_result.ok is False
        # Standalone must fail at the tampered index (core returns False without index)
        assert standalone_result.failed_index == TAMPER_IDX

    @needs_liboqs
    def test_hybrid_both_agree_verified(self) -> None:
        """On a valid hybrid chain, both aevum-core and standalone report VERIFIED."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain as standalone_verify

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        events = [
            chain.new_event(event_type=f"conformance.hybrid.{i}", payload={"i": i}, actor="test")
            for i in range(3)
        ]

        core_result = chain.verify_chain(events)
        entries = [dataclasses.asdict(e) for e in events]
        standalone_result = standalone_verify(
            entries,
            ed25519_pub=ds.ed25519_public_key,
            mldsa_pub=ds.mldsa65_public_key,
        )

        assert core_result is True
        assert standalone_result.ok is True

    @needs_liboqs
    def test_hybrid_tamper_both_agree_failed_at_same_index(self) -> None:
        """On a tampered hybrid chain, both fail; standalone at the correct index."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        from aevum.verify import verify_chain as standalone_verify

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        events = [
            chain.new_event(event_type=f"conformance.hybrid_tamper.{i}", payload={"i": i}, actor="test")
            for i in range(4)
        ]

        TAMPER_IDX = 1
        entries = copy.deepcopy([dataclasses.asdict(e) for e in events])
        entries[TAMPER_IDX]["actor"] = "FORGED_ACTOR"

        tampered_events = list(events)
        tampered_events[TAMPER_IDX] = dataclasses.replace(events[TAMPER_IDX], actor="FORGED_ACTOR")

        core_result = chain.verify_chain(tampered_events)
        standalone_result = standalone_verify(entries, ed25519_pub=ds.ed25519_public_key, mldsa_pub=ds.mldsa65_public_key)

        assert core_result is False
        assert standalone_result.ok is False
        assert standalone_result.failed_index == TAMPER_IDX

    def test_genesis_hash_constant_matches(self) -> None:
        """Both packages compute the same GENESIS_HASH — no drift."""
        from aevum.core.audit.sigchain import GENESIS_HASH as CORE_GENESIS_HASH

        from aevum.verify import GENESIS_HASH as VERIFY_GENESIS_HASH
        assert VERIFY_GENESIS_HASH == CORE_GENESIS_HASH

    def test_domain_prefix_constant_matches(self) -> None:
        """Both packages use the same DOMAIN_PREFIX — no drift."""
        from aevum.core.audit.event import DOMAIN_PREFIX as CORE_DOMAIN_PREFIX

        from aevum.verify import DOMAIN_PREFIX as VERIFY_DOMAIN_PREFIX
        assert VERIFY_DOMAIN_PREFIX == CORE_DOMAIN_PREFIX


# ── Independence structural test ──────────────────────────────────────────────

class TestIndependence:
    def test_core_module_does_not_import_aevum_core(self) -> None:
        """The verifier's _core.py must not import aevum.core.audit.sigchain or any aevum.core module."""
        core_src = Path(__file__).parent.parent / "src" / "aevum" / "verify" / "_core.py"
        assert core_src.exists(), f"Expected _core.py at {core_src}"
        tree = ast.parse(core_src.read_text())
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("aevum."):
                violations.append(f"line {node.lineno}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("aevum."):
                        violations.append(f"line {node.lineno}: import {alias.name}")
        assert not violations, (
            "aevum-verify/_core.py must not import any aevum.* module. Found:\n"
            + "\n".join(violations)
        )

    def test_cli_module_does_not_import_aevum_core(self) -> None:
        """The CLI module must not import aevum.core either."""
        cli_src = Path(__file__).parent.parent / "src" / "aevum" / "verify" / "_cli.py"
        assert cli_src.exists()
        tree = ast.parse(cli_src.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("aevum.core"):
                pytest.fail(f"_cli.py imports aevum.core: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("aevum.core"):
                        pytest.fail(f"_cli.py imports aevum.core: import {alias.name}")

    def test_init_only_imports_from_verify_package(self) -> None:
        """The __init__.py only imports from aevum.verify._core, not from aevum.core.*."""
        init_src = Path(__file__).parent.parent / "src" / "aevum" / "verify" / "__init__.py"
        assert init_src.exists()
        tree = ast.parse(init_src.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("aevum.core"):
                pytest.fail(f"__init__.py imports aevum.core: from {node.module} import ...")


# ── CLI smoke tests ───────────────────────────────────────────────────────────

class TestCLISmoke:
    """CLI smoke: valid → exit 0; tampered → exit 1."""

    def _write_entries_json(self, tmp_path: Path, entries: list[dict[str, Any]], name: str) -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(entries))
        return p

    def _write_pubkey(self, tmp_path: Path, pub_hex: str, name: str) -> Path:
        p = tmp_path / name
        p.write_text(pub_hex)
        return p

    def _run_cli(self, argv: list[str]) -> int:
        """Run the CLI main() and return the exit code (from SystemExit)."""
        from aevum.verify._cli import main
        with patch("sys.argv", ["aevum-verify"] + argv):
            try:
                main()
                return 0
            except SystemExit as exc:
                return int(exc.code) if exc.code is not None else 0

    def test_valid_chain_exits_0(self, tmp_path: Path) -> None:
        chain, entries = _make_classical_chain(3)
        pub = _chain_ed25519_pub(chain)
        entries_file = self._write_entries_json(tmp_path, entries, "entries.json")
        pubkey_file = self._write_pubkey(tmp_path, pub.hex(), "ed25519.pub")
        code = self._run_cli([str(entries_file), "--ed25519-pubkey", str(pubkey_file)])
        assert code == 0

    def test_tampered_chain_exits_1(self, tmp_path: Path) -> None:
        chain, entries = _make_classical_chain(3)
        pub = _chain_ed25519_pub(chain)
        tampered = copy.deepcopy(entries)
        tampered[1]["event_type"] = "TAMPERED"
        entries_file = self._write_entries_json(tmp_path, tampered, "tampered.json")
        pubkey_file = self._write_pubkey(tmp_path, pub.hex(), "ed25519.pub")
        code = self._run_cli([str(entries_file), "--ed25519-pubkey", str(pubkey_file)])
        assert code == 1

    def test_bad_entries_file_exits_2(self, tmp_path: Path) -> None:
        chain, _ = _make_classical_chain(1)
        pub = _chain_ed25519_pub(chain)
        pubkey_file = self._write_pubkey(tmp_path, pub.hex(), "ed25519.pub")
        code = self._run_cli(["/nonexistent/file.json", "--ed25519-pubkey", str(pubkey_file)])
        assert code == 2

    def test_inline_hex_pubkey(self, tmp_path: Path) -> None:
        """--ed25519-pubkey accepts an inline hex string (not just file path)."""
        chain, entries = _make_classical_chain(2)
        pub = _chain_ed25519_pub(chain)
        entries_file = self._write_entries_json(tmp_path, entries, "entries.json")
        code = self._run_cli([str(entries_file), "--ed25519-pubkey", pub.hex()])
        assert code == 0

    @needs_liboqs
    def test_hybrid_valid_exits_0(self, tmp_path: Path) -> None:
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        events = [chain.new_event(event_type=f"cli.hybrid.{i}", payload={"i": i}, actor="test") for i in range(2)]
        dicts = [dataclasses.asdict(e) for e in events]

        entries_file = self._write_entries_json(tmp_path, dicts, "hybrid_entries.json")
        pubkey_file = self._write_pubkey(tmp_path, ds.ed25519_public_key.hex(), "ed25519.pub")
        mldsa_file = self._write_pubkey(tmp_path, ds.mldsa65_public_key.hex(), "mldsa.pub")
        code = self._run_cli([
            str(entries_file),
            "--ed25519-pubkey", str(pubkey_file),
            "--mldsa-pubkey", str(mldsa_file),
        ])
        assert code == 0

    @needs_liboqs
    def test_hybrid_forged_mldsa_pub_exits_1(self, tmp_path: Path) -> None:
        """CLI: hybrid entry with forged mldsa65_pub → exit 1."""
        from aevum.core.audit.sigchain import Sigchain
        from aevum.core.signing import DualSigner

        ds_legit = DualSigner.generate()
        chain = Sigchain(dual_signer=ds_legit)
        event = chain.new_event(event_type="cli.forged", payload={}, actor="test")
        entry = dataclasses.asdict(event)

        ds_forged = DualSigner.generate()
        forged_entry = copy.deepcopy(entry)
        forged_entry["mldsa65_pub"] = ds_forged.mldsa65_public_key.hex()

        entries_file = self._write_entries_json(tmp_path, [forged_entry], "forged.json")
        pubkey_file = self._write_pubkey(tmp_path, ds_legit.ed25519_public_key.hex(), "ed25519.pub")
        mldsa_file = self._write_pubkey(tmp_path, ds_legit.mldsa65_public_key.hex(), "mldsa.pub")
        code = self._run_cli([
            str(entries_file),
            "--ed25519-pubkey", str(pubkey_file),
            "--mldsa-pubkey", str(mldsa_file),
        ])
        assert code == 1
