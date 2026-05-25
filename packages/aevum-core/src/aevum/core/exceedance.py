# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
QAR/FOQA exceedance detection for AI agent sessions.

Analogous to a GDRAS (Ground Data Replay and Analysis System) in aviation (FAA AC 120-82).
The ExceedanceDetector processes receipts in order and emits ExceedanceEvents for
conditions that match the 15-type exceedance catalogue.

EX-10 and EX-14 are NOT implemented here — they require cross-session or cross-agent
context that is not available in a single per-session receipt stream. These exceedances
are detected by FOQABridge at the multi-session level (v0.8.0 target).
"""

from __future__ import annotations

import collections
import hashlib  # noqa: F401 — available for callers
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aevum.core.receipt import AevumReceipt


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class ExceedanceEvent:
    """
    An exceedance event detected by ExceedanceDetector.
    Analogous to a FOQA exceedance in aviation (FAA AC 120-82).
    """

    exceedance_id: str            # EX-01 through EX-15
    exceedance_name: str          # Human-readable name
    aviation_analogy: str         # The aviation FOQA equivalent
    session_id: str               # Pseudonymized session ID (via GatekeeperFilter)
    agent_id: str                 # Pseudonymized agent ID
    detected_at: str              # ISO 8601 timestamp
    receipt_hash: str             # SHA3-256 of the triggering receipt
    severity: str                 # LOW | MEDIUM | HIGH | CRITICAL
    details: dict[str, Any] = field(default_factory=dict)  # Exceedance-specific data


# Exceedance catalogue — 15 types, indexed by exceedance_id.
# EX-10 and EX-14 are marked deferred: they require cross-session/cross-agent
# context not available in a single receipt stream. Do not add per-session
# detection for these — use FOQABridge at the multi-session level.
EXCEEDANCE_CATALOGUE: dict[str, dict[str, Any]] = {
    "EX-01": {
        "name": "Tool Retry Loop",
        "aviation": "Unstable Approach",
        "severity": "MEDIUM",
        "description": "More than 3 tool call retries within 60 seconds",
    },
    "EX-02": {
        "name": "Forbidden Tool Invocation",
        "aviation": "Excessive Bank Angle",
        "severity": "HIGH",
        "description": "Cedar policy returned DENY for a tool invocation",
    },
    "EX-03": {
        "name": "Safety Barrier Trip",
        "aviation": "GPWS Alert",
        "severity": "CRITICAL",
        "description": "Any Aevum barrier returned DENY",
    },
    "EX-04": {
        "name": "Human Override Rejection",
        "aviation": "Hard Landing",
        "severity": "HIGH",
        "description": "Human reviewer rejected an agent action",
    },
    "EX-05": {
        "name": "Agent Refusal",
        "aviation": "Go-Around",
        "severity": "LOW",
        "description": "Agent abstained or refused to execute a task",
    },
    "EX-06": {
        "name": "Stale Model or Policy Version",
        "aviation": "Configuration Warning",
        "severity": "MEDIUM",
        "description": "Model or policy version is older than 30 days",
    },
    "EX-07": {
        "name": "Token Rate Outlier",
        "aviation": "Engine Exceedance",
        "severity": "MEDIUM",
        "description": "Input or output token rate exceeds 3σ from rolling baseline",
    },
    "EX-08": {
        "name": "Latency Outlier",
        "aviation": "Airspeed Exceedance",
        "severity": "MEDIUM",
        "description": "LLM call latency exceeds 3σ from rolling baseline",
    },
    "EX-09": {
        "name": "Context Window Overflow",
        "aviation": "Altitude Bust",
        "severity": "HIGH",
        "description": "Prompt token count exceeds model context window",
    },
    "EX-10": {
        "name": "Concurrent Conflicting Tool Calls",
        "aviation": "TCAS Resolution Advisory",
        "severity": "HIGH",
        "description": (
            "Multiple simultaneous tool calls with conflicting state mutations. "
            "DEFERRED (v0.8.0): requires cross-session context not available in a "
            "single receipt stream. Detected by FOQABridge at the multi-session level."
        ),
        "deferred": True,
    },
    "EX-11": {
        "name": "ODD Exit",
        "aviation": "ODD Exit",
        "severity": "CRITICAL",
        "description": "Agent operated outside its Operational Design Domain",
    },
    "EX-12": {
        "name": "Unacknowledged Transition Demand",
        "aviation": "Automation Handoff Refused",
        "severity": "HIGH",
        "description": "Agent issued TRANSITION_DEMAND with no handoff_to_agent_id",
    },
    "EX-13": {
        "name": "Minimum Risk Maneuver",
        "aviation": "Minimum Risk Maneuver",
        "severity": "CRITICAL",
        "description": "Agent triggered a minimum-risk fallback maneuver",
    },
    "EX-14": {
        "name": "Agent Communication Failure",
        "aviation": "Communications Failure",
        "severity": "HIGH",
        "description": (
            "Agent-to-agent message timed out or was lost. "
            "DEFERRED (v0.8.0): requires cross-agent message tracking not available "
            "in a single receipt stream. Track multi-agent A2A correlation in v0.8.0."
        ),
        "deferred": True,
    },
    "EX-15": {
        "name": "Primary Agent Failure",
        "aviation": "Crew Incapacitation",
        "severity": "CRITICAL",
        "description": "Primary agent failed and triggered failover",
    },
}


class ExceedanceDetector:
    """
    Stateful FOQA exceedance detector for AI agent receipts.
    Analogous to a GDRAS (Ground Data Replay and Analysis System) in aviation.

    Threading: NOT thread-safe. Use one detector per agent session or
    protect with a lock in multi-threaded deployments.

    The detector maintains rolling 60-second windows for time-based checks.
    It does NOT store receipts — it processes them in-order and updates state.

    EX-10 (Concurrent Conflicting Tool Calls) and EX-14 (Agent Communication
    Failure) are NOT detected by this class. Both require cross-session or
    cross-agent context. See FOQABridge for multi-session exceedance detection.
    Callers should not attempt to detect EX-10/EX-14 via this detector.
    """

    WINDOW_SECONDS = 60
    SIGMA_THRESHOLD = 3.0
    RETRY_THRESHOLD = 3
    STALE_POLICY_DAYS = 30
    CONTEXT_WINDOW_UTILIZATION_THRESHOLD = 0.95  # flag at 95% utilization

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        # Rolling window: deque of timestamp floats for simple count-based checks
        self._tool_retries: collections.deque[float] = collections.deque()
        # Rolling window: deque of (timestamp, value) tuples for sigma checks
        self._token_rates: collections.deque[tuple[float, float]] = collections.deque()
        self._latencies: collections.deque[tuple[float, float]] = collections.deque()
        self._exceedances: list[ExceedanceEvent] = []

    def process(self, receipt: AevumReceipt) -> list[ExceedanceEvent]:
        """
        Process one receipt. Returns list of ExceedanceEvents (may be empty).
        Call this in order for every receipt in a session.
        """
        now = time.time()
        detected: list[ExceedanceEvent] = []

        # EX-02, EX-03: barrier evaluations (stateless)
        if self._has_forbidden_tool(receipt):
            detected.append(self._make(receipt, "EX-02", now))
        if self._has_any_barrier_deny(receipt):
            detected.append(self._make(receipt, "EX-03", now))

        # EX-04: human override rejection (stateless)
        if receipt.human_override_action == "REJECT":
            detected.append(self._make(receipt, "EX-04", now))

        # EX-11: ODD exit (stateless)
        if receipt.handoff_type == "ODD_EXIT":
            detected.append(self._make(receipt, "EX-11", now))

        # EX-12: unacknowledged transition demand (stateless)
        if (receipt.handoff_type == "TRANSITION_DEMAND"
                and not receipt.handoff_to_agent_id):
            detected.append(self._make(receipt, "EX-12", now))

        # EX-13: minimum risk maneuver (stateless)
        if receipt.handoff_type == "MINIMUM_RISK":
            detected.append(self._make(receipt, "EX-13", now))

        # EX-15: primary agent failure (stateless)
        if receipt.handoff_type == "FAILURE":
            detected.append(self._make(receipt, "EX-15", now))

        # EX-01: tool retry loop (stateful — rolling window)
        if receipt.action.startswith("tool.retry") or "retry" in receipt.action.lower():
            self._tool_retries.append(now)
        self._evict(self._tool_retries, now)
        if len(self._tool_retries) > self.RETRY_THRESHOLD:
            detected.append(self._make(receipt, "EX-01", now,
                details={"retry_count": len(self._tool_retries)}))

        # EX-05: agent refusal/abstention (stateless heuristic)
        if receipt.action in ("tool.refuse", "agent.abstain", "task.reject"):
            detected.append(self._make(receipt, "EX-05", now))

        # EX-06: stale model/policy (stateless — compare dates)
        if self._is_stale(receipt.policy_version):
            detected.append(self._make(receipt, "EX-06", now,
                details={"policy_version": receipt.policy_version}))

        # EX-09: context window overflow (stateless — check payload_tokens if available)
        if self._is_context_overflow(receipt):
            detected.append(self._make(receipt, "EX-09", now))

        self._exceedances.extend(detected)
        return detected

    def process_metric(
        self,
        metric_name: str,
        value: float,
        receipt_hash: str = "",
    ) -> list[ExceedanceEvent]:
        """
        Process a numeric metric for rolling-window sigma checks.
        Separate from process() because metric values come from OTel, not receipts.

        metric_name: "token_rate" | "latency_ms"
        value: the measured value for this event
        receipt_hash: SHA3-256 of the associated receipt (for ExceedanceEvent linking)

        Returns list of ExceedanceEvents if a sigma threshold is crossed.
        """
        now = time.time()
        detected: list[ExceedanceEvent] = []
        if metric_name == "token_rate":
            self._token_rates.append((now, value))
            self._evict_pairs(self._token_rates, now)
            if self._is_sigma_outlier(self._token_rates, value):
                detected.append(ExceedanceEvent(
                    exceedance_id="EX-07",
                    exceedance_name=EXCEEDANCE_CATALOGUE["EX-07"]["name"],
                    aviation_analogy=EXCEEDANCE_CATALOGUE["EX-07"]["aviation"],
                    session_id=self._session_id,
                    agent_id="",
                    detected_at=_iso_now(),
                    receipt_hash=receipt_hash,
                    severity=EXCEEDANCE_CATALOGUE["EX-07"]["severity"],
                    details={"value": value, "threshold": self.SIGMA_THRESHOLD},
                ))
        elif metric_name == "latency_ms":
            self._latencies.append((now, value))
            self._evict_pairs(self._latencies, now)
            if self._is_sigma_outlier(self._latencies, value):
                detected.append(ExceedanceEvent(
                    exceedance_id="EX-08",
                    exceedance_name=EXCEEDANCE_CATALOGUE["EX-08"]["name"],
                    aviation_analogy=EXCEEDANCE_CATALOGUE["EX-08"]["aviation"],
                    session_id=self._session_id,
                    agent_id="",
                    detected_at=_iso_now(),
                    receipt_hash=receipt_hash,
                    severity=EXCEEDANCE_CATALOGUE["EX-08"]["severity"],
                    details={"latency_ms": value, "threshold": self.SIGMA_THRESHOLD},
                ))
        return detected

    def exceedances(self) -> list[ExceedanceEvent]:
        """Return all exceedances detected so far in this session."""
        return list(self._exceedances)

    # --- private helpers ---

    def _has_forbidden_tool(self, receipt: AevumReceipt) -> bool:
        return receipt.barrier_evaluations.get("ClassificationCeiling") == "DENY"

    def _has_any_barrier_deny(self, receipt: AevumReceipt) -> bool:
        return any(v == "DENY" for v in receipt.barrier_evaluations.values())

    def _is_stale(self, policy_version: str) -> bool:
        import re
        from datetime import date
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", policy_version)
        if not m:
            return False
        try:
            policy_date = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return (date.today() - policy_date).days > self.STALE_POLICY_DAYS
        except ValueError:
            return False

    def _is_context_overflow(self, receipt: AevumReceipt) -> bool:
        # barrier_evaluations is reused as a context carrier for adapter-injected metrics.
        d = receipt.barrier_evaluations
        prompt_tokens = int(d.get("prompt_tokens", 0) or 0)
        context_limit = int(d.get("context_window_size", 0) or 0)
        if not (prompt_tokens and context_limit):
            return False
        return bool(prompt_tokens / context_limit >= self.CONTEXT_WINDOW_UTILIZATION_THRESHOLD)

    def _is_sigma_outlier(
        self, window: collections.deque[tuple[float, float]], value: float
    ) -> bool:
        import statistics
        values = [v for _, v in window]
        if len(values) < 10:  # need minimum sample for meaningful σ
            return False
        mean = statistics.mean(values)
        stdev = statistics.stdev(values)
        if stdev == 0:
            return False
        return bool(abs(value - mean) > (self.SIGMA_THRESHOLD * stdev))

    def _evict(self, dq: collections.deque[float], now: float) -> None:
        while dq and (now - dq[0]) > self.WINDOW_SECONDS:
            dq.popleft()

    def _evict_pairs(
        self, dq: collections.deque[tuple[float, float]], now: float
    ) -> None:
        while dq and (now - dq[0][0]) > self.WINDOW_SECONDS:
            dq.popleft()

    def _make(
        self,
        receipt: AevumReceipt,
        exc_id: str,
        now: float,
        details: dict[str, Any] | None = None,
    ) -> ExceedanceEvent:
        cat = EXCEEDANCE_CATALOGUE[exc_id]
        return ExceedanceEvent(
            exceedance_id=exc_id,
            exceedance_name=cat["name"],
            aviation_analogy=cat["aviation"],
            session_id=self._session_id,
            agent_id=receipt.agent_id,
            detected_at=_iso_now(),
            receipt_hash=receipt.sigchain_entry_hash,
            severity=cat["severity"],
            details=details or {},
        )
