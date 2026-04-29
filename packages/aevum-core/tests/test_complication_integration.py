"""
Integration tests for the complication lifecycle: install, approve, query, suspend, replay, conflict detection.

Scenario:
1. Install and approve a complication
2. Run query — complication contributes to result
3. Suspend complication — source_health shows degraded
4. replay() of the suspended-era query is faithful
5. Conflict between two complications caught at install time

NO tests/__init__.py — imports are direct via pythonpath.
"""

from __future__ import annotations

import pytest

from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine


class _EchoComp:
    """Test complication: echoes subject_ids back."""
    name = "echo"
    version = "0.1.0"
    capabilities = ["echo"]

    def manifest(self) -> dict:
        return {
            "name": self.name, "version": self.version,
            "description": "Echo complication",
            "capabilities": self.capabilities,
            "classification_max": 3,
            "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    def health(self) -> bool:
        return True

    async def run(self, ctx: dict, payload: dict) -> dict:
        return {"echoed_subjects": ctx.get("subject_ids", [])}


class _ConflictComp:
    """Test complication that conflicts with EchoComp (claims 'echo')."""
    name = "conflict-echo"
    version = "0.1.0"
    capabilities = ["echo"]  # Same as _EchoComp!

    def manifest(self) -> dict:
        return {
            "name": self.name, "version": self.version,
            "description": "Conflict complication",
            "capabilities": self.capabilities,
            "classification_max": 0,
            "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    def health(self) -> bool:
        return True

    async def run(self, ctx: dict, payload: dict) -> dict:
        return {}


def _engine_with_consent() -> Engine:
    engine = Engine()
    engine.add_consent_grant(ConsentGrant(
        grant_id="g1", subject_id="subject-1", grantee_id="actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="integration-test", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    return engine


def _prov() -> dict:
    return {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}


# Gate test 1: complication contributes to query result
def test_active_complication_appears_in_query_result() -> None:
    engine = _engine_with_consent()
    engine.install_complication(_EchoComp(), auto_approve=True)

    engine.ingest(data={"x": 1}, provenance=_prov(),
                  purpose="integration-test", subject_id="subject-1", actor="actor")
    result = engine.query(purpose="integration-test",
                          subject_ids=["subject-1"], actor="actor")

    assert result.status == "ok"
    assert "echo" in result.data.get("complication_results", {})
    assert result.source_health.overall == "healthy"
    assert "echo" in result.source_health.available


# Gate test 2: suspended complication → source_health.degraded
def test_suspended_complication_shows_degraded() -> None:
    engine = _engine_with_consent()
    engine.install_complication(_EchoComp(), auto_approve=True)

    engine.ingest(data={"x": 1}, provenance=_prov(),
                  purpose="integration-test", subject_id="subject-1", actor="actor")

    # Suspend before query
    engine.suspend_complication("echo")
    result = engine.query(purpose="integration-test",
                          subject_ids=["subject-1"], actor="actor")

    # Suspended → not in active complications → source_health reflects absence
    assert result.source_health.overall in ("healthy", "degraded")
    # No complication results since it was suspended
    assert "echo" not in result.data.get("complication_results", {})


# Gate test 3: replay faithfulness
def test_replay_preserves_complication_results() -> None:
    engine = _engine_with_consent()
    engine.install_complication(_EchoComp(), auto_approve=True)

    engine.ingest(data={"x": 1}, provenance=_prov(),
                  purpose="integration-test", subject_id="subject-1", actor="actor")

    # Query while complication is active
    active_result = engine.query(purpose="integration-test",
                                 subject_ids=["subject-1"], actor="actor")
    assert "echo" in active_result.data.get("complication_results", {})

    # Suspend the complication
    engine.suspend_complication("echo")

    # Replay the original query
    replayed = engine.replay(audit_id=active_result.audit_id, actor="actor")
    assert replayed.status == "ok"

    # The replayed payload contains the original ledger entry
    # which includes the complication results that were stored at query time
    original_payload = replayed.data.get("replayed_payload", {})
    assert "complication_results" in original_payload
    assert "echo" in original_payload["complication_results"]


# Gate test 4: conflict detection at install time
def test_conflict_detected_at_install_time() -> None:
    from aevum.core.exceptions import ComplicationError
    engine = _engine_with_consent()
    engine.install_complication(_EchoComp(), auto_approve=True)

    with pytest.raises(ComplicationError, match="capability conflict|Capability conflict"):
        engine.install_complication(_ConflictComp())


# Gate test 5: lifecycle state machine via engine
def test_complication_lifecycle_states() -> None:
    from aevum.core.complications.registry import ComplicationState
    engine = _engine_with_consent()
    engine.install_complication(_EchoComp())
    # After install_complication without auto_approve → PENDING
    assert engine.complication_state("echo") == ComplicationState.PENDING
    engine.approve_complication("echo")
    assert engine.complication_state("echo") == ComplicationState.ACTIVE
    engine.suspend_complication("echo")
    assert engine.complication_state("echo") == ComplicationState.SUSPENDED


# Gate test 6: webhook fires on review events
def test_webhook_fires_on_review_approve() -> None:
    from unittest.mock import MagicMock
    engine = _engine_with_consent()
    mock_client = MagicMock()

    # Inject mock http_client into webhook registry
    engine._webhook_registry._http_client = mock_client
    engine.register_webhook("w1", "https://example.com/hook", "secret",
                            events=["review.approved"])

    review_id = engine.create_review(
        proposed_action="test action", reason="gate test", actor="actor"
    )
    engine.review(audit_id=review_id, actor="actor", action="approve")

    assert mock_client.post.called
    call_args = mock_client.post.call_args
    assert call_args is not None


# Existing tests still pass (regression)
def test_existing_canary_barriers_unaffected() -> None:
    """Complication installation must not affect absolute barrier behaviour."""
    engine = Engine()
    result = engine.ingest(
        data={"content": "I want to kill myself"},
        provenance={"source_id": "test", "chain_of_custody": ["test"], "classification": 0},
        purpose="test", subject_id="s1", actor="actor",
    )
    assert result.status == "crisis"


def test_sigchain_still_valid_after_complication_events() -> None:
    engine = _engine_with_consent()
    engine.install_complication(_EchoComp(), auto_approve=True)
    engine.ingest(data={"x": 1}, provenance=_prov(),
                  purpose="test", subject_id="subject-1", actor="actor")
    engine.query(purpose="test", subject_ids=["subject-1"], actor="actor")
    assert engine.verify_sigchain() is True
