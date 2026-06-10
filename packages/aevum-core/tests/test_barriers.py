# SPDX-License-Identifier: Apache-2.0
"""Tests for all five unconditional barriers."""

from __future__ import annotations

import pytest

from aevum.core import barriers
from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine


def _engine_with_consent() -> Engine:
    e = Engine()
    e.add_consent_grant(ConsentGrant(
        grant_id="g1", subject_id="s1", grantee_id="actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="barrier-testing", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z"))
    return e


def _prov() -> dict:  # type: ignore[type-arg]
    return {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}


@pytest.mark.parametrize("kw", list(barriers._CRISIS_KEYWORDS)[:3])
def test_barrier1_crisis(kw: str) -> None:
    e = _engine_with_consent()
    r = e.ingest(data={"content": kw}, provenance=_prov(), purpose="t", subject_id="s1", actor="actor")
    assert r.status == "crisis"
    assert r.confidence == 0.0


def test_barrier3_no_consent_ingest() -> None:
    e = Engine()
    r = e.ingest(data={"x": 1}, provenance=_prov(), purpose="t", subject_id="s1", actor="actor")
    assert r.status == "error"
    assert r.data["error_code"] == "consent_required"


def test_barrier3_no_consent_query() -> None:
    e = Engine()
    r = e.query(purpose="t", subject_ids=["s1"], actor="actor")
    assert r.status == "error"
    assert r.data["error_code"] == "consent_required"


def test_barrier4_delete_raises() -> None:
    from aevum.core.audit.ledger import InMemoryLedger
    from aevum.core.audit.sigchain import Sigchain
    from aevum.core.exceptions import BarrierViolationError
    ledger = InMemoryLedger(Sigchain())
    ledger.append(event_type="test.e", payload={}, actor="a")
    with pytest.raises(BarrierViolationError):
        del ledger["any"]


def test_barrier4_setitem_raises() -> None:
    from aevum.core.audit.ledger import InMemoryLedger
    from aevum.core.audit.sigchain import Sigchain
    from aevum.core.exceptions import BarrierViolationError
    ledger = InMemoryLedger(Sigchain())
    with pytest.raises(BarrierViolationError):
        ledger["k"] = "v"


def test_barrier5_no_provenance() -> None:
    e = _engine_with_consent()
    r = e.ingest(data={"x": 1}, provenance={}, purpose="t", subject_id="s1", actor="actor")
    assert r.status == "error"
    assert r.data["error_code"] == "provenance_required"


def test_barrier2_classification_blocks_above_clearance_query() -> None:
    e = _engine_with_consent()
    # Ingest a classification-3 subject (grant allows class-3 ingest).
    e.ingest(
        data={"content": "top secret"},
        provenance={"source_id": "src", "chain_of_custody": ["src"], "classification": 3},
        purpose="barrier-testing", subject_id="s1", actor="actor",
    )
    # Query it with clearance 0 → must BLOCK, not return a degraded/redacted view.
    r = e.query(purpose="barrier-testing", subject_ids=["s1"],
                actor="actor", classification_max=0)
    assert r.status == "error", "Barrier 2 must BLOCK above-clearance reads, not degrade"
    assert r.data["error_code"] == "classification_blocked"
    # The block must be recorded as a barrier.triggered (barrier=2) audit event.
    types = [ev["event_type"] for ev in e.get_ledger_entries()]
    assert "barrier.triggered" in types
    assert e.verify_sigchain() is True


def test_barrier2_absent_subject_is_not_blocked() -> None:
    e = _engine_with_consent()
    # Subject "s1" has consent but was never ingested → absent, NOT above-ceiling. Must not block.
    r = e.query(purpose="barrier-testing", subject_ids=["s1"],
                actor="actor", classification_max=0)
    assert r.status != "error", "Absent subjects must not trigger Barrier 2"


def test_barrier2_within_clearance_query_ok() -> None:
    e = _engine_with_consent()
    e.ingest(
        data={"content": "public"},
        provenance={"source_id": "src", "chain_of_custody": ["src"], "classification": 0},
        purpose="barrier-testing", subject_id="s1", actor="actor",
    )
    r = e.query(purpose="barrier-testing", subject_ids=["s1"],
                actor="actor", classification_max=0)
    assert r.status == "ok"
