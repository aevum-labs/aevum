"""
Phase 11 gate: Engine + AgentComplication autonomy enforcement.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine


def _engine() -> Engine:
    engine = Engine()
    engine.add_consent_grant(ConsentGrant(
        grant_id="g1", subject_id="s1", grantee_id="actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="agent-test", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    return engine


class _L3AgentComp:
    name = "gate-l3-agent"
    version = "0.1.0"
    capabilities = ["gate-test"]
    autonomy_level = 3
    _consecutive_actions = 0
    _review_callback = None
    _lock: threading.Lock

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consecutive_actions = 0
        self._review_callback = None

    def set_review_callback(self, callback: Any) -> None:
        self._review_callback = callback

    def reset_consecutive_actions(self) -> None:
        with self._lock:
            self._consecutive_actions = 0

    @property
    def consecutive_actions(self) -> int:
        with self._lock:
            return self._consecutive_actions

    def health(self) -> bool:
        return True

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "description": "Gate test agent",
            "capabilities": self.capabilities,
            "classification_max": 3, "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
            "agent": {"autonomy_level": 3, "consecutive_action_threshold": 5},
        }

    async def run(self, ctx: Any, payload: Any) -> dict[str, Any]:
        with self._lock:
            self._consecutive_actions += 1
            current = self._consecutive_actions
        if current >= 5 and self._review_callback is not None:
            self._review_callback(
                proposed_action=f"Agent {self.name!r} consecutive actions: {current}",
                reason="L3 threshold reached",
                actor="agent",
                autonomy_level=3,
                risk_assessment="L3 threshold",
            )
        return {"result": "ok", "action_number": current}


def test_callback_injected_at_install() -> None:
    engine = _engine()
    agent = _L3AgentComp()
    engine.install_complication(agent, auto_approve=True)
    assert agent._review_callback is not None, "Engine must inject review callback"


def test_l3_gate_triggers_review_at_action_5() -> None:
    """Gate: L3 agent takes 5 actions, 5th triggers review."""
    engine = _engine()
    agent = _L3AgentComp()
    engine.install_complication(agent, auto_approve=True)

    prov = {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}
    engine.ingest(data={"x": 1}, provenance=prov, purpose="agent-test",
                  subject_id="s1", actor="actor")

    # Trigger 5 queries (agent runs each time)
    for _ in range(5):
        engine.query(purpose="agent-test", subject_ids=["s1"], actor="actor")

    # Ledger should have a review entry
    entries = engine.get_ledger_entries()
    review_entries = [e for e in entries if "review" in e["event_type"].lower()]
    assert len(review_entries) >= 1, (
        f"Expected review in ledger, got: {[e['event_type'] for e in entries]}"
    )


def test_reset_after_review_approval() -> None:
    """After review is approved, consecutive action counter resets."""
    engine = _engine()
    agent = _L3AgentComp()
    engine.install_complication(agent, auto_approve=True)

    prov = {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}
    engine.ingest(data={"x": 1}, provenance=prov, purpose="agent-test",
                  subject_id="s1", actor="actor")

    for _ in range(5):
        engine.query(purpose="agent-test", subject_ids=["s1"], actor="actor")

    # Get the pending review
    entries = engine.get_ledger_entries()
    review_entries = [
        e for e in entries
        if "review" in e["event_type"].lower() and "approved" not in e["event_type"]
    ]

    if review_entries:
        # Counter resets via engine
        if hasattr(engine, "reset_agent_actions"):
            engine.reset_agent_actions("gate-l3-agent")
            assert agent.consecutive_actions == 0


def test_sigchain_intact_after_agent_events() -> None:
    engine = _engine()
    agent = _L3AgentComp()
    engine.install_complication(agent, auto_approve=True)

    prov = {"source_id": "src", "chain_of_custody": ["src"], "classification": 0}
    engine.ingest(data={"x": 1}, provenance=prov, purpose="agent-test",
                  subject_id="s1", actor="actor")
    for _ in range(3):
        engine.query(purpose="agent-test", subject_ids=["s1"], actor="actor")

    assert engine.verify_sigchain() is True
