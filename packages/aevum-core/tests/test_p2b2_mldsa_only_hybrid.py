# SPDX-License-Identifier: Apache-2.0
"""P2b-2 gate tests: ML-DSA-only hybrid verification; redundant ed25519_sig dropped.

Verifies:
  1. New hybrid entries have ed25519_sig=None, mldsa65_sig is not None; verify_chain True.
  2. Downgrade still caught: strip mldsa65_sig → False; tamper mldsa65_sig → False;
     flip key_scheme → False (P2a binding intact).
  3. Back-compat: old fmt==1 entry still carrying ed25519_sig → still True (ignored).
  4. Classical entry (key_scheme==ed25519) → True; primary Ed25519 still the proof.
  5. Legacy fmt==None synthetic entry (full DualSignature) → still True.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, SystemExit):
    pytest.skip(
        "liboqs native library not available — skipping P2b-2 ML-DSA-only hybrid tests",
        allow_module_level=True,
    )

from test_phase1_principles import make_test_principles_file


def _boot_kernel(tmp_path, sp_path):
    from aevum.core.kernel import Kernel
    return Kernel.local(
        state_dir=tmp_path / "state",
        principles_path=sp_path,
        tsa_enabled=False,
    )


class TestNewHybridEntryDropsEd25519Sig:
    def test_ed25519_sig_is_none_on_new_hybrid_entry(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.hybrid",
            payload={"test": "p2b2"},
            actor="test-suite",
        )

        assert event.key_scheme == "ed25519+ml-dsa-65"
        assert event.ed25519_sig is None, "ed25519_sig must be None (removed in P2b-2)"
        assert event.ed25519_pub is None, "ed25519_pub must be None (removed in P2b-2)"
        assert event.mldsa65_sig is not None, "mldsa65_sig must be populated"
        assert event.mldsa65_pub is not None, "mldsa65_pub must be populated"

    def test_verify_chain_true_for_new_hybrid_entry(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        events = [
            kernel.sigchain.new_event(
                event_type=f"p2b2.verify.{i}",
                payload={"i": i},
                actor="test-suite",
            )
            for i in range(3)
        ]

        assert kernel.sigchain.verify_chain(events) is True


class TestDowngradeDefenses:
    def test_strip_mldsa65_sig_returns_false(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.downgrade.strip",
            payload={"probe": "strip"},
            actor="test-suite",
        )
        tampered = dataclasses.replace(event, mldsa65_sig=None)

        assert kernel.sigchain.verify_chain([tampered]) is False

    def test_tamper_mldsa65_sig_returns_false(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.downgrade.tamper",
            payload={"probe": "tamper"},
            actor="test-suite",
        )
        # Flip the last byte of the ML-DSA-65 signature
        bad_sig = bytes.fromhex(event.mldsa65_sig)
        bad_sig = bad_sig[:-1] + bytes([bad_sig[-1] ^ 0xFF])
        tampered = dataclasses.replace(event, mldsa65_sig=bad_sig.hex())

        assert kernel.sigchain.verify_chain([tampered]) is False

    def test_flip_key_scheme_returns_false(self, tmp_path):
        """P2a binding: changing key_scheme from hybrid to classical must fail (signed field)."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="p2b2.downgrade.scheme",
            payload={"probe": "scheme"},
            actor="test-suite",
        )
        # Flip from hybrid to classical — invalidates the primary Ed25519 signature
        tampered = dataclasses.replace(event, key_scheme="ed25519")

        assert kernel.sigchain.verify_chain([tampered]) is False


class TestBackCompat:
    def test_old_fmt1_entry_with_ed25519_sig_still_verifies(self, tmp_path):
        """Old fmt==1 entries that carry ed25519_sig must still pass (field ignored, not required)."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        # Produce a fresh hybrid entry, then inject ed25519_sig/ed25519_pub to simulate
        # an old entry that still carries those fields.
        event = kernel.sigchain.new_event(
            event_type="p2b2.compat.old_ed25519",
            payload={"probe": "old-fmt1"},
            actor="test-suite",
        )
        # Inject plausible (but not verified) ed25519 fields — they must be silently ignored
        dummy_ed25519_sig = "aa" * 64   # 128 hex chars = 64 bytes
        dummy_ed25519_pub = "bb" * 32   # 64 hex chars = 32 bytes
        old_style = dataclasses.replace(
            event,
            ed25519_sig=dummy_ed25519_sig,
            ed25519_pub=dummy_ed25519_pub,
        )

        # verify_chain must return True — ed25519_sig is ignored, not required
        assert kernel.sigchain.verify_chain([old_style]) is True

    def test_classical_entry_key_scheme_ed25519_verifies(self, tmp_path):
        """Classical entry with key_scheme==ed25519 and no dual fields must verify True."""
        from aevum.core.audit.sigchain import Sigchain

        chain = Sigchain()  # no dual_signer → classical-only entries
        events = [
            chain.new_event(event_type=f"p2b2.classical.{i}", payload={"i": i}, actor="test-suite")
            for i in range(3)
        ]

        assert all(e.key_scheme == "ed25519" for e in events)
        assert all(e.mldsa65_sig is None for e in events)
        assert chain.verify_chain(events) is True


class TestLegacyFmtNonePath:
    def test_legacy_synthetic_entry_still_verifies(self, tmp_path):
        """Legacy fmt==None entries (full DualSignature) continue to pass verify_chain.

        Constructs a genuine legacy-style entry: 16-field primary signing, with all four
        DualSignature fields populated, sig_format_version=None.  The legacy verify_chain
        path must accept it unchanged (ed25519_sig + mldsa65_sig both verified).
        """
        import base64

        from aevum.core.audit.event import AuditEvent
        from aevum.core.audit.hlc import now as hlc_now
        from aevum.core.audit.sigchain import GENESIS_HASH, Sigchain
        from aevum.core.signing import DualSigner

        # Generate a fresh DualSigner and wire it into a Sigchain via as_primary_signer()
        dual = DualSigner.generate()
        primary = dual.as_primary_signer()
        chain = Sigchain(signer=primary, dual_signer=dual)

        # Build 16-field signing_fields (the legacy format — no key_scheme / sig_format_version)
        event_id = "00000000-0000-7000-8000-000000000001"
        ep_id    = "00000000-0000-7000-8000-000000000002"
        ts       = hlc_now()
        payload  = {"probe": "legacy-synthetic"}
        payload_hash = AuditEvent.hash_payload(payload)
        base_fields = {
            "event_id": event_id,
            "episode_id": ep_id,
            "sequence": 1,
            "event_type": "p2b2.legacy.synthetic",
            "schema_version": "1.0",
            "valid_from": "2026-01-01T00:00:00+00:00",
            "valid_to": None,
            "system_time": ts,
            "causation_id": None,
            "correlation_id": None,
            "actor": "test-suite",
            "trace_id": None,
            "span_id": None,
            "payload_hash": payload_hash,
            "prior_hash": GENESIS_HASH,
            "signer_key_id": primary.key_id,
        }
        canonical = json.dumps(base_fields, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha3_256(canonical).digest()
        sig = base64.urlsafe_b64encode(primary.sign(digest)).rstrip(b"=").decode()

        # Produce a DualSignature over the same canonical bytes
        dual_sig = dual.sign(canonical)
        DualSigner.verify(canonical, dual_sig)  # sanity

        # Construct the legacy AuditEvent (sig_format_version=None → legacy path)
        legacy_event = AuditEvent(
            event_id=event_id,
            episode_id=ep_id,
            sequence=1,
            event_type="p2b2.legacy.synthetic",
            schema_version="1.0",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_to=None,
            system_time=ts,
            causation_id=None,
            correlation_id=None,
            actor="test-suite",
            trace_id=None,
            span_id=None,
            payload=payload,
            payload_hash=payload_hash,
            prior_hash=GENESIS_HASH,
            signature=sig,
            signer_key_id=primary.key_id,
            ed25519_sig=dual_sig.ed25519_sig.hex(),
            mldsa65_sig=dual_sig.mldsa65_sig.hex(),
            ed25519_pub=dual_sig.ed25519_pub.hex(),
            mldsa65_pub=dual_sig.mldsa65_pub.hex(),
            sig_format_version=None,
        )

        assert chain.verify_chain([legacy_event]) is True
