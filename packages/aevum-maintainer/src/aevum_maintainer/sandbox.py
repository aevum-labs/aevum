# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
In-memory sandbox state for the four-step demo flow.

Ported faithfully from demo/sandbox_state.py and demo/sandbox_models.py.

A7 compliance: this module never imports from aevum.core and is never
connected to a production sigchain. Each actor (X-Demo-Actor header value)
gets an isolated SandboxState so concurrent demo users do not interfere.
"""

import hashlib
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic request / response models (from demo/sandbox_models.py)
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    model_config = {"json_schema_extra": {
        "example": {"host_id": "ACME-3318", "scan_type": "fund_transfer"},
    }}
    host_id: str = Field(
        description="The subject or account the requested action targets.",
        examples=["ACME-3318", "CUST-7741", "ACCT-0091"],
    )
    scan_type: Literal[
        "fund_transfer", "pii_access", "trade_execution",
        "diagnostic", "memory_pressure", "cert_check",
    ] = Field(
        default="fund_transfer",
        description="The governed action the agent is requesting.",
    )


class ConsentRequest(BaseModel):
    task_id: str = Field(description="Task ID returned by /sandbox/scan")
    decision: Literal["approve", "deny"] = Field(
        description="Approve or deny the proposed remediation.",
    )


class ExecuteRequest(BaseModel):
    task_id: str = Field(description="Task ID returned by /sandbox/scan")
    consent_token: str = Field(description="Consent token returned by /sandbox/consent")


class ScanResult(BaseModel):
    task_id: str
    host_id: str
    finding: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    proposed_action: str
    barriers_evaluated: dict[str, str]
    receipt_hash: str


class ConsentResult(BaseModel):
    task_id: str
    decision: str
    consent_token: str
    valid_for_seconds: int


class ExecuteResult(BaseModel):
    task_id: str
    outcome: str
    sigchain_head: str
    rekor_entry: str
    receipt_hash: str


class SigchainEntry(BaseModel):
    sequence: int
    action: str
    principal: str
    occurred_at: str
    sigchain_entry_hash: str
    handoff_type: str | None
    barrier_evaluations: dict[str, str]


class SigchainResult(BaseModel):
    head_hash: str
    entry_count: int
    entries: list[SigchainEntry]


# ---------------------------------------------------------------------------
# Sandbox state (from demo/sandbox_state.py)
# ---------------------------------------------------------------------------


@dataclass
class SandboxTask:
    task_id: str
    host_id: str
    finding: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    proposed_action: str
    status: str = "pending_consent"
    consent_token: str | None = None
    receipt_hash: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class SandboxState:
    """
    In-memory sandbox state. Resets on server restart.
    Max 1000 tasks (oldest evicted if exceeded — ring buffer).
    Never connected to production sigchain (A7).
    """

    MAX_TASKS = 1000

    def __init__(self) -> None:
        self._tasks: OrderedDict[str, SandboxTask] = OrderedDict()
        self._sigchain: list[dict[str, Any]] = []
        self._seed()

    def _seed(self) -> None:
        task = SandboxTask(
            task_id=f"tsk_{secrets.token_urlsafe(12)}",
            host_id="ACME-3318",
            finding="Agent initiated a $25,000 wire to a newly added beneficiary",
            severity="CRITICAL",
            proposed_action="Execute the outbound wire transfer",
        )
        self._tasks[task.task_id] = task
        self._add_sigchain_entry("scan.complete", "sandbox-scanner", task.task_id)

    def create_task(self, host_id: str, scan_type: str) -> SandboxTask:
        findings = {
            "fund_transfer": (
                "Agent initiated a $25,000 wire to a newly added beneficiary",
                "CRITICAL",
                "Execute the outbound wire transfer",
            ),
            "pii_access": (
                "Agent requested a bulk export of 1,240 customer records (PII)",
                "HIGH",
                "Release the customer records to the requesting agent",
            ),
            "trade_execution": (
                "Agent submitted a $180,000 equity order outside its mandate bands",
                "HIGH",
                "Route the order to the exchange",
            ),
            "diagnostic": (
                "Disk utilization at 94% — /var/log partition",
                "HIGH",
                "Rotate and compress logs older than 7 days",
            ),
            "memory_pressure": (
                "RSS memory leak in worker-pool-3: +2.1 GB/hr",
                "CRITICAL",
                "Restart worker-pool-3 with memory cap",
            ),
            "cert_check": (
                "TLS certificate expires in 6 days: api.example.com",
                "MEDIUM",
                "Renew certificate via ACME",
            ),
        }
        finding, severity, action = findings.get(
            scan_type,
            ("Unrecognised condition on host", "LOW", "Manual inspection required"),
        )
        task = SandboxTask(
            task_id=f"tsk_{secrets.token_urlsafe(12)}",
            host_id=host_id,
            finding=finding,
            severity=severity,
            proposed_action=action,
        )
        if len(self._tasks) >= self.MAX_TASKS:
            self._tasks.popitem(last=False)
        self._tasks[task.task_id] = task
        self._add_sigchain_entry("scan.complete", "sandbox-scanner", task.task_id)
        return task

    def consent(self, task_id: str, decision: str) -> SandboxTask:
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"task {task_id} not found")
        if decision == "approve":
            task.status = "approved"
            task.consent_token = f"cst_{secrets.token_urlsafe(16)}"
        else:
            task.status = "denied"
        self._add_sigchain_entry(
            f"consent.{decision}", "sandbox-reviewer", task_id,
            handoff_type="HUMAN_OVERRIDE",
        )
        return task

    def execute(self, task_id: str, consent_token: str) -> SandboxTask:
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"task {task_id} not found")
        if task.status != "approved":
            raise ValueError("task not approved")
        if task.consent_token != consent_token:
            raise ValueError("invalid consent token")
        task.status = "executed"
        task.receipt_hash = hashlib.sha3_256(
            f"{task_id}:{consent_token}:{task.host_id}".encode()
        ).hexdigest()
        self._add_sigchain_entry("tool.execute", "sandbox-executor", task_id)
        return task

    def sigchain(self) -> list[dict[str, Any]]:
        return list(self._sigchain)

    def _add_sigchain_entry(
        self,
        action: str,
        principal: str,
        task_id: str,
        handoff_type: str | None = None,
    ) -> None:
        seq = len(self._sigchain)
        prior = self._sigchain[-1]["sigchain_entry_hash"] if self._sigchain else "0" * 64
        entry_hash = hashlib.sha3_256(
            f"{seq}:{action}:{principal}:{task_id}:{prior}".encode()
        ).hexdigest()
        self._sigchain.append({
            "sequence": seq,
            "action": action,
            "principal": principal,
            "occurred_at": datetime.now(UTC).isoformat(),
            "sigchain_entry_hash": entry_hash,
            "handoff_type": handoff_type,
            "barrier_evaluations": {
                "Crisis": "ALLOW",
                "Consent": "ALLOW",
                "ClassificationCeiling": "ALLOW",
                "AuditImmutability": "ALLOW",
                "Provenance": "ALLOW",
            },
        })


# ---------------------------------------------------------------------------
# Per-actor sandbox registry (supports concurrent demo users)
# ---------------------------------------------------------------------------

_sandboxes: dict[str, SandboxState] = {}
_ALLOWED_ACTORS = frozenset({"demo-agent", "intruder-agent", "demo-human"})


def get_sandbox(actor: str) -> SandboxState:
    """Return (or create) the SandboxState for this actor. Never touches production sigchain."""
    clean = actor if actor in _ALLOWED_ACTORS else "demo-agent"
    if clean not in _sandboxes:
        _sandboxes[clean] = SandboxState()
    return _sandboxes[clean]


def reset_sandbox(actor: str) -> SandboxState:
    """Discard and recreate the SandboxState for this actor."""
    clean = actor if actor in _ALLOWED_ACTORS else "demo-agent"
    _sandboxes[clean] = SandboxState()
    return _sandboxes[clean]
