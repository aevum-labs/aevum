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
