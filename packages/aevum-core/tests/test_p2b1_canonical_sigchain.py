# SPDX-License-Identifier: Apache-2.0
"""P2b-1 gate tests: kernel owns the canonical sigchain with stable persisted identity.

Verifies four properties:
  1. kernel.sigchain exists and produces hybrid entries (key_scheme=ed25519+ml-dsa-65).
  2. The primary signature in the sigchain verifies under the persisted Ed25519 key.
  3. verify_chain() returns True (chain integrity).
  4. RESTART PROOF — a second Kernel.local() from the same state dir verifies the chain
     produced by the first process (stable identity, no ephemeral-key defect).
"""
from __future__ import annotations

import asyncio
import base64
import sqlite3

import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, SystemExit):
    pytest.skip(
        "liboqs native library not available — skipping P2b-1 canonical sigchain tests",
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


class TestKernelOwnsSigchain:
    def test_sigchain_property_exists(self, tmp_path):
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)
        from aevum.core.audit.sigchain import Sigchain
        assert hasattr(kernel, "sigchain")
        assert isinstance(kernel.sigchain, Sigchain)

    def test_canonical_entry_is_hybrid(self, tmp_path):
        """sigchain.new_event() produces key_scheme=ed25519+ml-dsa-65 with mldsa65_sig."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="test.canonical",
            payload={"test": "p2b1"},
            actor="test-suite",
        )

        assert event.key_scheme == "ed25519+ml-dsa-65", (
            f"Expected hybrid scheme, got {event.key_scheme!r}"
        )
        assert event.mldsa65_sig is not None, "mldsa65_sig must be populated"
        assert not hasattr(event, "ed25519_sig"), "ed25519_sig must not exist on AuditEvent (P2f)"

    def test_primary_signature_verifies_under_persisted_key(self, tmp_path):
        """The primary Ed25519 signature in the chain entry verifies under the kernel's key."""
        import hashlib
        import json

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        event = kernel.sigchain.new_event(
            event_type="test.primary_sig",
            payload={"probe": "primary"},
            actor="test-suite",
        )

        # Reconstruct the signing_fields exactly as Sigchain.new_event builds them
        signing_fields = {
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
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": event.sig_format_version,
        }
        canonical = json.dumps(signing_fields, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha3_256(canonical).digest()

        sig_bytes = base64.urlsafe_b64decode(event.signature + "==")

        # Verify with the persisted Ed25519 public key
        pub_bytes = kernel.signer.ed25519_public_key
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        # Raises InvalidSignature on failure — test fails if this raises
        public_key.verify(sig_bytes, digest)

    def test_verify_chain_returns_true(self, tmp_path):
        """verify_chain() is True after appending entries to the canonical chain."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        events = [
            kernel.sigchain.new_event(
                event_type=f"test.event.{i}",
                payload={"i": i},
                actor="test-suite",
            )
            for i in range(3)
        ]

        assert kernel.sigchain.verify_chain(events), "verify_chain must return True"


class TestRestartStability:
    """Proof that the ephemeral-key defect is gone: chain from process A verifies in process B."""

    def test_chain_verifies_after_kernel_restart(self, tmp_path):
        """Boot kernel, write entries, reload kernel from same state dir, verify chain."""
        sp_path, _ = make_test_principles_file(tmp_path)

        # Process A: generate keys, write events
        kernel_a = _boot_kernel(tmp_path, sp_path)
        events_from_a = [
            kernel_a.sigchain.new_event(
                event_type=f"test.restart.{i}",
                payload={"round": i, "process": "A"},
                actor="process-A",
            )
            for i in range(3)
        ]
        pub_key_a = kernel_a.signer.ed25519_public_key

        # Process B: reload the same keys (simulates restart)
        kernel_b = _boot_kernel(tmp_path, sp_path)
        pub_key_b = kernel_b.signer.ed25519_public_key

        # Keys must be identical (stable identity)
        assert pub_key_a == pub_key_b, (
            "Ed25519 public key changed between kernel boots — key not persisted correctly"
        )

        # Process B's sigchain must verify Process A's events
        assert kernel_b.sigchain.verify_chain(events_from_a), (
            "Chain produced in process A must verify in process B — ephemeral-key defect present"
        )

    def test_key_id_stable_across_restarts(self, tmp_path):
        """The signer_key_id in sigchain entries is stable across process restarts."""
        sp_path, _ = make_test_principles_file(tmp_path)

        kernel_a = _boot_kernel(tmp_path, sp_path)
        event_a = kernel_a.sigchain.new_event(
            event_type="test.key_id_a",
            payload={"boot": 1},
            actor="test-suite",
        )

        kernel_b = _boot_kernel(tmp_path, sp_path)
        event_b = kernel_b.sigchain.new_event(
            event_type="test.key_id_b",
            payload={"boot": 2},
            actor="test-suite",
        )

        assert event_a.signer_key_id == event_b.signer_key_id, (
            f"signer_key_id changed between boots: {event_a.signer_key_id!r} vs {event_b.signer_key_id!r}"
        )


class TestSessionSigchainIntegration:
    """Session._append_to_sigchain goes live and sigchain_entry_id is populated."""

    def test_sigchain_entry_id_populated_in_sqlite(self, tmp_path):
        """After a session closes, sigchain_entry_id in the sessions table is not NULL."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        from aevum.core.session import Session
        db_path = tmp_path / "sessions.db"

        async def run():
            async with Session(actor="test-suite", kernel=kernel, db_path=db_path):
                pass

        asyncio.run(run())

        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT sigchain_entry_id FROM sessions LIMIT 1"
        ).fetchone()
        conn.close()

        assert row is not None, "No session row written to SQLite"
        assert row[0] is not None, (
            "sigchain_entry_id is NULL — sigchain append did not produce an entry id"
        )

    def test_kernel_engine_factory_uses_canonical_sigchain(self, tmp_path):
        """Kernel.engine() returns an Engine whose sigchain IS the kernel's canonical chain."""
        sp_path, _ = make_test_principles_file(tmp_path)
        kernel = _boot_kernel(tmp_path, sp_path)

        from aevum.core.engine import Engine
        engine = kernel.engine()
        assert isinstance(engine, Engine)
        # The engine's sigchain object must be the same instance as kernel.sigchain
        assert engine._sigchain is kernel.sigchain, (  # type: ignore[attr-defined]
            "Engine created via Kernel.engine() must share the kernel's canonical sigchain"
        )
