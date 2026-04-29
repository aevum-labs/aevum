"""
Canary tests — fail if any absolute barrier is removed or softened.
Spec Section 09.4. These must pass on every commit to aevum-core.
"""

from __future__ import annotations

import pytest

from aevum.core import barriers
from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine


def _engine() -> Engine:
    e = Engine()
    e.add_consent_grant(ConsentGrant(
        grant_id="canary", subject_id="s-canary", grantee_id="canary-actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="canary-testing", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z"))
    return e


def _prov() -> dict:  # type: ignore[type-arg]
    return {"source_id": "canary-src", "chain_of_custody": ["canary-src"], "classification": 0}


def test_canary_barrier1_keywords_present() -> None:
    assert len(barriers._CRISIS_KEYWORDS) > 0, "CANARY FAIL: Crisis keywords empty — Barrier 1 compromised"
    e = _engine()
    kw = next(iter(barriers._CRISIS_KEYWORDS))
    r = e.ingest(data={"content": kw}, provenance=_prov(), purpose="canary", subject_id="s-canary", actor="canary-actor")
    assert r.status == "crisis", "CANARY FAIL: crisis keyword did not trigger Barrier 1"


def test_canary_barrier3_consent_required() -> None:
    e = Engine()
    r = e.ingest(data={"content": "normal"}, provenance=_prov(), purpose="canary", subject_id="s-canary", actor="canary-actor")
    assert r.status == "error" and r.data["error_code"] == "consent_required", \
        "CANARY FAIL: Barrier 3 (Consent) bypassed"


def test_canary_barrier4_ledger_immutable() -> None:
    from aevum.core.audit.ledger import InMemoryLedger
    from aevum.core.audit.sigchain import Sigchain
    from aevum.core.exceptions import BarrierViolationError
    ledger = InMemoryLedger(Sigchain())
    ledger.append(event_type="canary.e", payload={}, actor="canary")
    with pytest.raises(BarrierViolationError, match="Barrier 4"):
        del ledger["any"]


def test_canary_barrier5_provenance_required() -> None:
    e = _engine()
    r = e.ingest(data={"content": "normal"}, provenance={}, purpose="canary", subject_id="s-canary", actor="canary-actor")
    assert r.status == "error" and r.data["error_code"] == "provenance_required", \
        "CANARY FAIL: Barrier 5 (Provenance) bypassed"


def test_canary_all_barrier_functions_exist() -> None:
    assert callable(barriers.check_crisis), "CANARY: check_crisis missing"
    assert callable(barriers.apply_classification_ceiling), "CANARY: classification ceiling missing"
    assert callable(barriers.check_consent), "CANARY: check_consent missing"
    assert callable(barriers.check_provenance), "CANARY: check_provenance missing"
    from aevum.core.audit.ledger import InMemoryLedger
    assert hasattr(InMemoryLedger, "__delitem__"), "CANARY: ledger __delitem__ guard missing"
    assert hasattr(InMemoryLedger, "__setitem__"), "CANARY: ledger __setitem__ guard missing"
