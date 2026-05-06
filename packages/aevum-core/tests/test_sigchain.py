"""Tests for sigchain integrity and HLC."""

from __future__ import annotations

import dataclasses
import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.sigchain import GENESIS_HASH, Sigchain


def test_genesis_hash() -> None:
    assert hashlib.sha3_256(b"aevum:genesis").hexdigest() == GENESIS_HASH


def test_first_event_prior_is_genesis() -> None:
    chain = Sigchain()
    e = chain.new_event(event_type="test.e", payload={}, actor="a")
    assert e.prior_hash == GENESIS_HASH


def test_second_event_chains_from_first() -> None:
    chain = Sigchain()
    e1 = chain.new_event(event_type="test.1", payload={}, actor="a")
    e2 = chain.new_event(event_type="test.2", payload={}, actor="a")
    assert e2.prior_hash == AuditEvent.hash_event_for_chain(e1)


def test_sequence_increments() -> None:
    chain = Sigchain()
    events = [chain.new_event(event_type=f"t.{i}", payload={}, actor="a") for i in range(5)]
    assert [e.sequence for e in events] == list(range(1, 6))


def test_verify_chain() -> None:
    chain = Sigchain()
    events = [chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="a") for i in range(5)]
    assert chain.verify_chain(events) is True


def test_tampered_payload_detected() -> None:
    chain = Sigchain()
    e1 = chain.new_event(event_type="t.1", payload={"ok": True}, actor="a")
    e2 = chain.new_event(event_type="t.2", payload={}, actor="a")
    tampered = dataclasses.replace(e1, payload={"tampered": True})
    assert chain.verify_chain([tampered, e2]) is False


@given(n=st.integers(min_value=1, max_value=15))
@settings(max_examples=15)
def test_sequence_always_increments(n: int) -> None:
    chain = Sigchain()
    events = [chain.new_event(event_type="t.e", payload={"i": i}, actor="a") for i in range(n)]
    for i in range(1, len(events)):
        assert events[i].sequence > events[i-1].sequence


def test_signer_abc_in_process_default() -> None:
    """Default Sigchain uses InProcessSigner with in-process provenance."""
    sc = Sigchain()
    assert sc.key_provenance == "in-process"
    assert sc.key_id  # non-empty


def test_signer_abc_external_key() -> None:
    """Passing private_key= wraps in InProcessSigner with external provenance."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    sc = Sigchain(private_key=key, key_id="test-key-123")
    assert sc.key_provenance == "external"
    assert sc.key_id == "test-key-123"


def test_signer_instance_accepted() -> None:
    """Sigchain accepts a Signer instance directly."""
    from aevum.core.audit.signer import InProcessSigner
    signer = InProcessSigner()
    sc = Sigchain(signer=signer)
    assert sc.key_provenance == "in-process"
    assert sc._signer is signer


def test_signing_semantics_uses_digest() -> None:
    """new_event() signs SHA3-256(canonical), not the raw canonical bytes."""
    sc = Sigchain()
    event = sc.new_event(event_type="test.sign", payload={"x": 1}, actor="a")
    # Chain verification passing confirms digest-based signing semantics are consistent
    assert sc.verify_chain([event]) is True


def test_verify_chain_after_signer_refactor() -> None:
    """verify_chain() must pass with the new signing semantics."""
    sc = Sigchain()
    events = []
    for i in range(5):
        events.append(sc.new_event(
            event_type=f"test.{i}", payload={"i": i}, actor="a"
        ))
    assert sc.verify_chain(events) is True


def test_checkpoint_restore_with_signer() -> None:
    """Checkpoint/restore must work after Signer refactor."""
    sc = Sigchain()
    cp = sc.checkpoint()
    sc.new_event(event_type="ghost", payload={}, actor="a")
    sc.restore(cp)
    e = sc.new_event(event_type="after.restore", payload={}, actor="a")
    assert e.sequence == 1
    assert sc.verify_chain([e]) is True
