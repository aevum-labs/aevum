# SPDX-License-Identifier: Apache-2.0
"""Tests for ExceedanceEvent, EXCEEDANCE_CATALOGUE, and ExceedanceDetector."""

from __future__ import annotations

import time

import pytest

from aevum.core.exceedance import (
    EXCEEDANCE_CATALOGUE,
    ExceedanceDetector,
    ExceedanceEvent,
)
from aevum.core.receipt import AevumReceipt

# ── Helpers ───────────────────────────────────────────────────────────────────

def _receipt(**kwargs) -> AevumReceipt:
    """Build a minimal AevumReceipt; override any field via kwargs."""
    defaults = dict(
        sigchain_entry_hash="a" * 64,
        action="tool.call",
        principal="agent-test",
        prior_hash="b" * 64,
        occurred_at="2026-05-25T00:00:00+00:00",
        agent_id="agent-001",
        sequence=1,
        barrier_evaluations={},
    )
    defaults.update(kwargs)
    return AevumReceipt(**defaults)


def _detector(session_id: str = "sess-test") -> ExceedanceDetector:
    return ExceedanceDetector(session_id)


# ── Catalogue ─────────────────────────────────────────────────────────────────

class TestExceedanceCatalogue:
    def test_all_15_types_present(self):
        assert len(EXCEEDANCE_CATALOGUE) == 15

    def test_ids_ex01_through_ex15(self):
        expected = {f"EX-{i:02d}" for i in range(1, 16)}
        assert set(EXCEEDANCE_CATALOGUE.keys()) == expected

    def test_each_entry_has_required_fields(self):
        for exc_id, entry in EXCEEDANCE_CATALOGUE.items():
            assert "name" in entry, f"{exc_id} missing name"
            assert "aviation" in entry, f"{exc_id} missing aviation"
            assert "severity" in entry, f"{exc_id} missing severity"
            assert "description" in entry, f"{exc_id} missing description"

    def test_severity_values_valid(self):
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for exc_id, entry in EXCEEDANCE_CATALOGUE.items():
            assert entry["severity"] in valid, f"{exc_id} has invalid severity"

    def test_ex10_marked_deferred(self):
        assert EXCEEDANCE_CATALOGUE["EX-10"].get("deferred") is True
        assert "DEFERRED" in EXCEEDANCE_CATALOGUE["EX-10"]["description"]

    def test_ex14_marked_deferred(self):
        assert EXCEEDANCE_CATALOGUE["EX-14"].get("deferred") is True
        assert "DEFERRED" in EXCEEDANCE_CATALOGUE["EX-14"]["description"]


# ── ExceedanceEvent dataclass ──────────────────────────────────────────────────

class TestExceedanceEvent:
    def test_frozen_immutable(self):
        ev = ExceedanceEvent(
            exceedance_id="EX-03",
            exceedance_name="Safety Barrier Trip",
            aviation_analogy="GPWS Alert",
            session_id="sess-1",
            agent_id="agent-1",
            detected_at="2026-05-25T00:00:00+00:00",
            receipt_hash="abc123",
            severity="CRITICAL",
        )
        with pytest.raises((AttributeError, TypeError)):
            ev.severity = "LOW"  # type: ignore[misc]

    def test_details_defaults_empty(self):
        ev = ExceedanceEvent(
            exceedance_id="EX-01",
            exceedance_name="Tool Retry Loop",
            aviation_analogy="Unstable Approach",
            session_id="s",
            agent_id="a",
            detected_at="2026-05-25T00:00:00+00:00",
            receipt_hash="x",
            severity="MEDIUM",
        )
        assert ev.details == {}


# ── Stateless exceedances ─────────────────────────────────────────────────────

class TestStatelessExceedances:
    def test_ex02_forbidden_tool_classification_ceiling(self):
        det = _detector()
        r = _receipt(barrier_evaluations={"ClassificationCeiling": "DENY"})
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-02" in ids

    def test_ex02_not_triggered_when_allowed(self):
        det = _detector()
        r = _receipt(barrier_evaluations={"ClassificationCeiling": "ALLOW"})
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-02" not in ids

    def test_ex03_any_barrier_deny(self):
        det = _detector()
        r = _receipt(barrier_evaluations={"SomePolicyBarrier": "DENY"})
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-03" in ids

    def test_ex03_and_ex02_both_fire_for_classification_ceiling(self):
        det = _detector()
        r = _receipt(barrier_evaluations={"ClassificationCeiling": "DENY"})
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-02" in ids
        assert "EX-03" in ids

    def test_ex03_not_triggered_when_all_allow(self):
        det = _detector()
        r = _receipt(barrier_evaluations={"A": "ALLOW", "B": "ALLOW"})
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-03" not in ids

    def test_ex04_human_override_reject(self):
        det = _detector()
        r = _receipt(human_override_action="REJECT")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-04" in ids

    def test_ex04_not_triggered_for_approve(self):
        det = _detector()
        r = _receipt(human_override_action="APPROVE")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-04" not in ids

    def test_ex05_agent_abstain(self):
        det = _detector()
        r = _receipt(action="agent.abstain")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-05" in ids

    def test_ex05_tool_refuse(self):
        det = _detector()
        r = _receipt(action="tool.refuse")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-05" in ids

    def test_ex05_task_reject(self):
        det = _detector()
        r = _receipt(action="task.reject")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-05" in ids

    def test_ex05_not_triggered_for_normal_action(self):
        det = _detector()
        r = _receipt(action="tool.call")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-05" not in ids

    def test_ex06_stale_policy_version(self):
        det = _detector()
        # Use a policy version dated well before the STALE_POLICY_DAYS threshold
        r = _receipt(policy_version="policy-2025-01-01")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-06" in ids

    def test_ex06_recent_policy_not_stale(self):
        det = _detector()
        # Use a very recent date (0 days old) — well within 30 days
        from datetime import date, timedelta
        recent = (date.today() - timedelta(days=5)).isoformat()
        r = _receipt(policy_version=f"policy-{recent}")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-06" not in ids

    def test_ex06_opaque_version_not_stale(self):
        det = _detector()
        r = _receipt(policy_version="v3")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-06" not in ids

    def test_ex06_details_contain_policy_version(self):
        det = _detector()
        r = _receipt(policy_version="policy-2025-01-01")
        result = det.process(r)
        ex06 = next(e for e in result if e.exceedance_id == "EX-06")
        assert "policy_version" in ex06.details

    def test_ex09_context_overflow_at_threshold(self):
        det = _detector()
        r = _receipt(barrier_evaluations={
            "prompt_tokens": 190000,
            "context_window_size": 200000,
        })
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-09" in ids

    def test_ex09_not_triggered_below_threshold(self):
        det = _detector()
        r = _receipt(barrier_evaluations={
            "prompt_tokens": 100000,
            "context_window_size": 200000,
        })
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-09" not in ids

    def test_ex09_missing_fields_not_triggered(self):
        det = _detector()
        r = _receipt(barrier_evaluations={})
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-09" not in ids

    def test_ex11_odd_exit(self):
        det = _detector()
        r = _receipt(handoff_type="ODD_EXIT")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-11" in ids

    def test_ex12_transition_demand_without_handoff_to(self):
        det = _detector()
        r = _receipt(handoff_type="TRANSITION_DEMAND", handoff_to_agent_id=None)
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-12" in ids

    def test_ex12_not_triggered_with_handoff_to(self):
        det = _detector()
        r = _receipt(handoff_type="TRANSITION_DEMAND", handoff_to_agent_id="agent-002")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-12" not in ids

    def test_ex13_minimum_risk(self):
        det = _detector()
        r = _receipt(handoff_type="MINIMUM_RISK")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-13" in ids

    def test_ex15_primary_agent_failure(self):
        det = _detector()
        r = _receipt(handoff_type="FAILURE")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-15" in ids


# ── Stateful: EX-01 tool retry loop ───────────────────────────────────────────

class TestEX01RetryLoop:
    def test_ex01_triggers_after_threshold(self):
        det = _detector()
        # Process 4 retry receipts (> RETRY_THRESHOLD of 3)
        for _ in range(4):
            det.process(_receipt(action="tool.retry"))
        result = det.process(_receipt(action="tool.retry"))
        ids = [e.exceedance_id for e in result]
        assert "EX-01" in ids

    def test_ex01_not_triggered_at_threshold(self):
        det = _detector()
        for _ in range(3):
            det.process(_receipt(action="tool.retry"))
        result = det.process(_receipt(action="tool.call"))  # non-retry
        ids = [e.exceedance_id for e in result]
        assert "EX-01" not in ids

    def test_ex01_details_contain_retry_count(self):
        det = _detector()
        for _ in range(5):
            result = det.process(_receipt(action="tool.retry"))
        ex01 = next((e for e in result if e.exceedance_id == "EX-01"), None)
        assert ex01 is not None
        assert "retry_count" in ex01.details
        assert ex01.details["retry_count"] > 3

    def test_ex01_case_insensitive_retry_match(self):
        det = _detector()
        for _ in range(4):
            det.process(_receipt(action="tool.RETRY"))
        result = det.process(_receipt(action="tool.RETRY"))
        ids = [e.exceedance_id for e in result]
        assert "EX-01" in ids

    def test_ex01_window_eviction(self, monkeypatch):
        det = _detector()
        # Simulate old retries that are outside the 60s window
        old_time = time.time() - 120
        for _ in range(5):
            det._tool_retries.append(old_time)
        # These should be evicted; no EX-01 after fresh empty window
        result = det.process(_receipt(action="tool.call"))
        ids = [e.exceedance_id for e in result]
        assert "EX-01" not in ids


# ── Stateful: EX-07 token rate sigma ─────────────────────────────────────────

class TestEX07TokenRateSigma:
    def test_ex07_triggers_on_outlier(self):
        det = _detector()
        # Build baseline: 10 values centered around 100
        baseline = [100.0, 99.0, 101.0, 100.0, 98.0, 102.0, 100.0, 99.0, 101.0, 100.0]
        for v in baseline:
            result = det.process_metric("token_rate", v)
            assert result == []
        # Now submit an extreme outlier
        result = det.process_metric("token_rate", 500.0)
        ids = [e.exceedance_id for e in result]
        assert "EX-07" in ids

    def test_ex07_not_triggered_below_minimum_samples(self):
        det = _detector()
        # Fewer than 10 samples → no sigma check
        for _v in [100.0, 99.0, 101.0]:
            result = det.process_metric("token_rate", 500.0)
            assert result == []

    def test_ex07_details_contain_value_and_threshold(self):
        det = _detector()
        baseline = [100.0, 99.0, 101.0, 100.0, 98.0, 102.0, 100.0, 99.0, 101.0, 100.0]
        for v in baseline:
            det.process_metric("token_rate", v)
        result = det.process_metric("token_rate", 500.0)
        ex07 = next(e for e in result if e.exceedance_id == "EX-07")
        assert "value" in ex07.details
        assert "threshold" in ex07.details

    def test_ex07_session_id_preserved(self):
        det = ExceedanceDetector("my-session-123")
        baseline = [100.0] * 10
        for v in baseline:
            det.process_metric("token_rate", v)
        # All same → stdev=0 → no outlier; use varied baseline
        det2 = ExceedanceDetector("my-session-123")
        for v in [100.0, 99.0, 101.0, 100.0, 98.0, 102.0, 100.0, 99.0, 101.0, 100.0]:
            det2.process_metric("token_rate", v)
        result = det2.process_metric("token_rate", 500.0)
        if result:
            assert result[0].session_id == "my-session-123"


# ── Stateful: EX-08 latency sigma ─────────────────────────────────────────────

class TestEX08LatencySigma:
    def test_ex08_triggers_on_outlier(self):
        det = _detector()
        baseline = [50.0, 49.0, 51.0, 50.0, 48.0, 52.0, 50.0, 49.0, 51.0, 50.0]
        for v in baseline:
            det.process_metric("latency_ms", v)
        result = det.process_metric("latency_ms", 5000.0)
        ids = [e.exceedance_id for e in result]
        assert "EX-08" in ids

    def test_ex08_details_contain_latency_ms(self):
        det = _detector()
        baseline = [50.0, 49.0, 51.0, 50.0, 48.0, 52.0, 50.0, 49.0, 51.0, 50.0]
        for v in baseline:
            det.process_metric("latency_ms", v)
        result = det.process_metric("latency_ms", 5000.0)
        ex08 = next(e for e in result if e.exceedance_id == "EX-08")
        assert "latency_ms" in ex08.details


# ── Deferred exceedances: EX-10 and EX-14 ─────────────────────────────────────

class TestDeferredExceedances:
    def test_ex10_not_detected_by_per_session_detector(self):
        """EX-10 requires cross-session context — not detectable here."""
        det = _detector()
        # No combination of receipt fields will trigger EX-10 from ExceedanceDetector
        r = _receipt(action="tool.concurrent_mutation")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-10" not in ids

    def test_ex14_not_detected_by_per_session_detector(self):
        """EX-14 requires cross-agent message tracking — not detectable here."""
        det = _detector()
        r = _receipt(action="agent.message.timeout")
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        assert "EX-14" not in ids

    def test_ex10_catalogue_entry_documents_deferral(self):
        assert "DEFERRED" in EXCEEDANCE_CATALOGUE["EX-10"]["description"]
        assert EXCEEDANCE_CATALOGUE["EX-10"].get("deferred") is True

    def test_ex14_catalogue_entry_documents_deferral(self):
        assert "DEFERRED" in EXCEEDANCE_CATALOGUE["EX-14"]["description"]
        assert EXCEEDANCE_CATALOGUE["EX-14"].get("deferred") is True


# ── ExceedanceDetector state management ───────────────────────────────────────

class TestDetectorState:
    def test_exceedances_accumulate(self):
        det = _detector()
        det.process(_receipt(handoff_type="MINIMUM_RISK"))
        det.process(_receipt(handoff_type="ODD_EXIT"))
        all_exc = det.exceedances()
        ids = [e.exceedance_id for e in all_exc]
        assert "EX-13" in ids
        assert "EX-11" in ids

    def test_exceedances_returns_copy(self):
        det = _detector()
        det.process(_receipt(handoff_type="FAILURE"))
        first = det.exceedances()
        # Mutating the returned list does not affect internal state
        first.clear()
        second = det.exceedances()
        assert len(second) > 0

    def test_empty_process_returns_empty(self):
        det = _detector()
        result = det.process(_receipt())
        assert isinstance(result, list)

    def test_event_fields_populated(self):
        det = ExceedanceDetector("session-xyz")
        r = _receipt(agent_id="agent-abc", handoff_type="FAILURE")
        result = det.process(r)
        ex = next(e for e in result if e.exceedance_id == "EX-15")
        assert ex.session_id == "session-xyz"
        assert ex.agent_id == "agent-abc"
        assert ex.severity == "CRITICAL"
        assert ex.receipt_hash == "a" * 64
        assert ex.detected_at != ""

    def test_process_metric_unknown_name_returns_empty(self):
        det = _detector()
        result = det.process_metric("unknown_metric", 999.0)
        assert result == []

    def test_multiple_exceedances_same_receipt(self):
        det = _detector()
        r = _receipt(
            handoff_type="ODD_EXIT",
            human_override_action="REJECT",
            barrier_evaluations={"ClassificationCeiling": "DENY"},
        )
        result = det.process(r)
        ids = [e.exceedance_id for e in result]
        # EX-02, EX-03, EX-04, EX-11 should all fire
        assert "EX-02" in ids
        assert "EX-03" in ids
        assert "EX-04" in ids
        assert "EX-11" in ids


# ── SigChain integration ───────────────────────────────────────────────────────

class TestSigchainWiring:
    def test_sigchain_accepts_exceedance_detector_param(self):
        from aevum.core.audit.sigchain import Sigchain
        det = ExceedanceDetector("sess-sigchain")
        chain = Sigchain(exceedance_detector=det)
        assert chain is not None

    def test_sigchain_works_without_exceedance_detector(self):
        from aevum.core.audit.sigchain import Sigchain
        chain = Sigchain()
        event = chain.new_event(
            event_type="test.event",
            payload={"key": "value"},
            actor="agent-test",
        )
        assert event.event_id is not None

    def test_sigchain_with_exceedance_detector_no_receipt_cbor(self):
        """Without receipt_encoder, no receipt_cbor → exceedance detector not called."""
        from unittest.mock import MagicMock

        from aevum.core.audit.sigchain import Sigchain
        mock_detector = MagicMock(spec=ExceedanceDetector)
        chain = Sigchain(exceedance_detector=mock_detector)
        chain.new_event(
            event_type="test.event",
            payload={"key": "value"},
            actor="agent-test",
        )
        # Without receipt_cbor, process() should not be called
        mock_detector.process.assert_not_called()
