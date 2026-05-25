"""
In-memory sandbox state for the four-step demo flow.

Sandbox state is per-process. Multi-worker deployments have independent
sandboxes per worker. For demo purposes this is acceptable.

A7 compliance: this module never imports from aevum.core and is never
connected to a production sigchain.
"""

import hashlib
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class SandboxTask:
    task_id: str
    host_id: str
    finding: str
    severity: str
    proposed_action: str
    status: str = "pending_consent"   # pending_consent | approved | denied | executed
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
        self._sigchain: list[dict] = []
        self._seed()

    def _seed(self) -> None:
        """Pre-seed with a realistic finding so first GET /sandbox/sigchain has entries."""
        task = SandboxTask(
            task_id=f"tsk_{secrets.token_urlsafe(12)}",
            host_id="host-42",
            finding="Disk utilization at 94% — /var/log partition",
            severity="HIGH",
            proposed_action="Rotate and compress logs older than 7 days",
        )
        self._tasks[task.task_id] = task
        self._add_sigchain_entry(
            action="scan.complete",
            principal="sandbox-scanner",
            task_id=task.task_id,
        )

    def create_task(self, host_id: str, scan_type: str) -> SandboxTask:
        findings = {
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
            self._tasks.popitem(last=False)  # evict oldest
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
        self._add_sigchain_entry(
            "tool.execute", "sandbox-executor", task_id,
            handoff_type=None,
        )
        return task

    def sigchain(self) -> list[dict]:
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


# Module-level singleton — created once at import. Resets on server restart (A7).
_sandbox = SandboxState()


def get_sandbox() -> SandboxState:
    return _sandbox
