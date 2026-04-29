"""
A2A task format — Pydantic model and state machine for agent-to-agent task exchange.

Task states: created, working, input_required, completed, failed, cancelled.
Task IDs map directly to Aevum audit_ids for provenance tracking.
A full A2A HTTP server is not included; the MCP tools provide the integration surface.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


A2ATaskState = Literal[
    "created", "working", "input_required", "completed", "failed", "cancelled"
]


class A2AMessage(BaseModel):
    model_config = ConfigDict(frozen=True)
    role: Literal["user", "agent"]
    content: str
    timestamp: str | None = None


class A2AArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)
    artifact_id: str
    name: str
    content: str
    mime_type: str = "text/plain"


class A2ATask(BaseModel):
    """
    A2A-compatible task representation.

    The aevum audit_id maps to the A2A task_id.
    Task state maps to ledger event types:
        created       -> commit(event_type="agent.task.created")
        working       -> commit(event_type="agent.task.working")
        input_required -> pending_review (review_required=True)
        completed     -> commit(event_type="agent.task.completed")
        failed        -> commit(event_type="agent.task.failed")
        cancelled     -> commit(event_type="agent.task.cancelled")
    """

    model_config = ConfigDict(frozen=True)

    task_id: str                      # maps to aevum audit_id
    name: str
    state: A2ATaskState
    description: str = ""
    messages: list[A2AMessage] = []
    artifacts: list[A2AArtifact] = []
    metadata: dict[str, Any] = {}

    @classmethod
    def created(cls, task_id: str, name: str, description: str = "") -> "A2ATask":
        return cls(task_id=task_id, name=name, state="created", description=description)

    @classmethod
    def completed(
        cls,
        task_id: str,
        name: str,
        result: str,
        artifacts: list[A2AArtifact] | None = None,
    ) -> "A2ATask":
        return cls(
            task_id=task_id,
            name=name,
            state="completed",
            messages=[A2AMessage(role="agent", content=result)],
            artifacts=artifacts or [],
        )

    @classmethod
    def input_required(cls, task_id: str, name: str, prompt: str) -> "A2ATask":
        return cls(
            task_id=task_id,
            name=name,
            state="input_required",
            messages=[A2AMessage(role="agent", content=prompt)],
        )

    @classmethod
    def failed(cls, task_id: str, name: str, error: str) -> "A2ATask":
        return cls(
            task_id=task_id,
            name=name,
            state="failed",
            messages=[A2AMessage(role="agent", content=f"Task failed: {error}")],
        )
