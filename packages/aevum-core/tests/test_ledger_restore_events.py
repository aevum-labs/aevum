# SPDX-License-Identifier: Apache-2.0
"""Tests for InMemoryLedger.restore_events() / Engine.restore_events() /
Engine.get_last_committed_event() -- re-hydrating already-signed events
without re-signing them, so a persisted sigchain survives a process restart
byte-for-byte."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import GENESIS_HASH, Sigchain
from aevum.core.engine import Engine


def _sigchain_with_key() -> tuple[Sigchain, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    return Sigchain(private_key=key, key_id="test-persistent-key"), key


class TestLedgerRestoreEvents:
    def test_restore_events_is_byte_identical(self) -> None:
        sc, _ = _sigchain_with_key()
        ledger = InMemoryLedger(sc)
        original = ledger.append(event_type="t.1", payload={"a": 1}, actor="a")

        sc2 = Sigchain(signer=sc._signer)
        restored_ledger = InMemoryLedger(sc2)
        restored_ledger.restore_events([original])

        assert restored_ledger.get(original.audit_id()) == original
        assert restored_ledger.all_events() == [original]

    def test_restore_events_empty_is_noop(self) -> None:
        sc, _ = _sigchain_with_key()
        ledger = InMemoryLedger(sc)
        ledger.restore_events([])
        assert ledger.all_events() == []
        assert ledger.count() == 0

    def test_new_commit_after_restore_continues_chain(self) -> None:
        sc, key = _sigchain_with_key()
        original_ledger = InMemoryLedger(sc)
        e1 = original_ledger.append(event_type="t.1", payload={}, actor="a")
        e2 = original_ledger.append(event_type="t.2", payload={}, actor="a")

        sc2 = Sigchain(private_key=key, key_id="test-persistent-key")
        restored_ledger = InMemoryLedger(sc2)
        restored_ledger.restore_events([e1, e2])

        e3 = restored_ledger.append(event_type="t.3", payload={}, actor="a")
        assert e3.sequence == 3
        from aevum.core.audit.event import AuditEvent
        assert e3.prior_hash == AuditEvent.hash_event_for_chain(e2)

    def test_verify_chain_passes_on_mixed_restored_and_new_chain(self) -> None:
        sc, key = _sigchain_with_key()
        original_ledger = InMemoryLedger(sc)
        history = [
            original_ledger.append(event_type=f"t.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]

        sc2 = Sigchain(private_key=key, key_id="test-persistent-key")
        restored_ledger = InMemoryLedger(sc2)
        restored_ledger.restore_events(history)
        new_event = restored_ledger.append(event_type="t.new", payload={}, actor="a")

        mixed_chain = restored_ledger.all_events()
        assert mixed_chain == [*history, new_event]
        assert sc2.verify_chain(mixed_chain) is True

    def test_restore_events_requires_same_signing_key_to_verify(self) -> None:
        """Restoring under a DIFFERENT key than the one that produced the events
        does not corrupt the events themselves, but verify_chain (which checks
        signatures against the *current* signer's public key) must fail --
        this is the exact failure mode Part A must never trigger for the
        no-persistent-key path (a fresh ephemeral key each boot)."""
        sc, _ = _sigchain_with_key()
        original_ledger = InMemoryLedger(sc)
        history = [original_ledger.append(event_type="t.1", payload={}, actor="a")]

        different_sc = Sigchain()  # a different, unrelated key
        restored_ledger = InMemoryLedger(different_sc)
        restored_ledger.restore_events(history)

        assert different_sc.verify_chain(restored_ledger.all_events()) is False

    def test_first_restored_event_prior_hash_is_genesis(self) -> None:
        sc, key = _sigchain_with_key()
        original_ledger = InMemoryLedger(sc)
        e1 = original_ledger.append(event_type="t.1", payload={}, actor="a")
        assert e1.prior_hash == GENESIS_HASH


class TestEngineRestoreEvents:
    def test_restore_events_delegates_to_ledger(self) -> None:
        sc, key = _sigchain_with_key()
        source_ledger = InMemoryLedger(sc)
        history = [source_ledger.append(event_type="t.1", payload={}, actor="a")]

        sc2 = Sigchain(private_key=key, key_id="test-persistent-key")
        engine = Engine(sigchain=sc2)
        engine.restore_events(history)

        restored_ids = {entry["audit_id"] for entry in engine.get_ledger_entries()}
        assert history[0].audit_id() in restored_ids

    def test_restore_events_raises_when_ledger_lacks_support(self) -> None:
        """A ledger backend that has no restore_events() of its own (e.g. a
        future PostgresLedger before it grows one) must fail loud, not
        silently no-op -- a silent no-op would look like a successful
        restart-safe restore while leaving every "restored" event missing."""
        sc, _ = _sigchain_with_key()
        delegate = InMemoryLedger(sc)

        class _NoRestoreLedger:
            """Wraps a real ledger but deliberately has no restore_events."""

            def append(self, **kwargs):
                return delegate.append(**kwargs)

            def get(self, audit_id):
                return delegate.get(audit_id)

            def all_events(self):
                return delegate.all_events()

            def count(self):
                return delegate.count()

            def last_audit_id(self):
                return delegate.last_audit_id()

            def max_sequence_for_subjects(self, subject_ids):
                return delegate.max_sequence_for_subjects(subject_ids)

            def __delitem__(self, key):
                del delegate[key]

            def __setitem__(self, key, value):
                delegate[key] = value

        engine = Engine(ledger=_NoRestoreLedger())
        with pytest.raises(NotImplementedError):
            engine.restore_events([])

    def test_get_last_committed_event_returns_none_when_empty(self) -> None:
        sc, _ = _sigchain_with_key()
        # A fresh Engine always writes session.start, so the ledger is never
        # truly empty -- exercise the underlying ledger method directly for
        # the empty case, and the Engine wrapper for the non-empty case.
        ledger = InMemoryLedger(sc)
        assert ledger.last_audit_id() is None

    def test_get_last_committed_event_matches_envelope_audit_id(self) -> None:
        engine = Engine()
        envelope = engine.commit(event_type="app.test_event", payload={"k": "v"}, actor="tester")
        assert envelope.status == "ok"
        # The documented pitfall this method exists to avoid: audit_id is a
        # top-level OutputEnvelope field, never a key inside envelope.data.
        assert "audit_id" not in envelope.data
        last = engine.get_last_committed_event()
        assert last is not None
        assert last.audit_id() == envelope.audit_id

    def test_get_last_committed_event_reflects_most_recent_of_several(self) -> None:
        engine = Engine()
        engine.commit(event_type="app.first", payload={}, actor="tester")
        second = engine.commit(event_type="app.second", payload={}, actor="tester")
        last = engine.get_last_committed_event()
        assert last is not None
        assert last.audit_id() == second.audit_id
        assert last.event_type == "app.second"
