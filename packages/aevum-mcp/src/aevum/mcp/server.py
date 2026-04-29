"""
Aevum MCP server — five functions + two A2A task tools.

Phase 11 adds:
  create_task(name, description, payload) -> A2ATask (state=created)
  get_task(task_id) -> A2ATask (polls ledger for task state)
"""

from __future__ import annotations

from typing import Any

from aevum.core.engine import Engine
from aevum.mcp.a2a import A2ATask
from mcp.server.fastmcp import FastMCP


def create_server(engine: Engine | None = None) -> FastMCP:
    """
    Create the Aevum MCP server.

    Args:
        engine: Aevum kernel. Uses Engine() with in-memory defaults if None.

    Returns:
        Configured FastMCP server instance.
    """
    _engine = engine or Engine()
    mcp = FastMCP("aevum")

    @mcp.tool()
    def ingest(
        data: dict[str, Any],
        provenance: dict[str, Any],
        purpose: str,
        subject_id: str,
        actor: str = "mcp-user",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Move data through the governed membrane into the Aevum knowledge graph.

        Requires an active consent grant for the actor + subject_id + purpose.
        Returns an OutputEnvelope with status (ok/error/crisis) and audit_id.
        """
        result = _engine.ingest(
            data=data,
            provenance=provenance,
            purpose=purpose,
            subject_id=subject_id,
            actor=actor,
            idempotency_key=idempotency_key,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    def query(
        purpose: str,
        subject_ids: list[str],
        actor: str = "mcp-user",
        classification_max: int = 0,
    ) -> dict[str, Any]:
        """
        Traverse the Aevum knowledge graph and return context for the declared purpose.

        Requires consent grants for all subject_ids. Results are filtered by
        classification_max (Barrier 2). Active complications contribute to results.
        Returns an OutputEnvelope with the assembled context.
        """
        result = _engine.query(
            purpose=purpose,
            subject_ids=subject_ids,
            actor=actor,
            classification_max=classification_max,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    def review(
        audit_id: str,
        action: str | None = None,
        actor: str = "mcp-user",
    ) -> dict[str, Any]:
        """
        Get status of or act on a pending human review gate.

        action: None = poll status, "approve" = approve, "veto" = veto.
        Veto-as-default: if a deadline was set and has elapsed, silence = veto.
        Returns an OutputEnvelope with review status.
        """
        result = _engine.review(
            audit_id=audit_id,
            actor=actor,
            action=action,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    def commit(
        event_type: str,
        payload: dict[str, Any],
        actor: str = "mcp-user",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Append an event to the Aevum episodic ledger.

        event_type must not use kernel-reserved prefixes (ingest., query., etc.).
        Use a namespaced prefix: "myapp.user_action", "myapp.decision", etc.
        Returns an OutputEnvelope with the new entry's audit_id.
        """
        result = _engine.commit(
            event_type=event_type,
            payload=payload,
            actor=actor,
            idempotency_key=idempotency_key,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    def replay(
        audit_id: str,
        actor: str = "mcp-user",
    ) -> dict[str, Any]:
        """
        Reconstruct a past Aevum decision faithfully.

        Returns the original ledger entry payload as it existed at the time
        it was recorded. The reconstruction is deterministic and read-only.
        Requires consent for the replay operation on the original subject.
        """
        result = _engine.replay(
            audit_id=audit_id,
            actor=actor,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    def create_task(
        name: str,
        description: str = "",
        payload: dict[str, Any] | None = None,
        actor: str = "mcp-user",
    ) -> dict[str, Any]:
        """
        Create an A2A-compatible task and record it in the Aevum ledger.

        The returned task_id is an aevum audit_id (urn:aevum:audit:...).
        Poll task status with get_task(task_id).
        Task state transitions are tracked via ledger events.
        """
        committed = _engine.commit(
            event_type="agent.task.created",
            payload={
                "name": name,
                "description": description,
                "task_payload": payload or {},
            },
            actor=actor,
        )
        task = A2ATask.created(
            task_id=committed.audit_id,
            name=name,
            description=description,
        )
        return task.model_dump(mode="json")

    @mcp.tool()
    def get_task(
        task_id: str,
        actor: str = "mcp-user",
    ) -> dict[str, Any]:
        """
        Get the current state of an A2A task by its audit_id.

        Replays the ledger entry to reconstruct task state.
        Returns an A2ATask with the current state and any messages.
        """
        replayed = _engine.replay(audit_id=task_id, actor=actor)

        if replayed.status == "error":
            task = A2ATask.failed(
                task_id=task_id,
                name="unknown",
                error=replayed.data.get("error_detail", "Task not found"),
            )
            return task.model_dump(mode="json")

        original_payload = replayed.data.get("replayed_payload", {})
        name = original_payload.get("name", "task")

        # Map ledger event_type to A2A state
        event_type = original_payload.get("event_type", "agent.task.created")
        state_map = {
            "agent.task.created": "created",
            "agent.task.working": "working",
            "agent.task.completed": "completed",
            "agent.task.failed": "failed",
            "agent.task.cancelled": "cancelled",
        }
        a2a_state = state_map.get(event_type, "created")

        task = A2ATask(
            task_id=task_id,
            name=name,
            state=a2a_state,  # type: ignore[arg-type]
            description=original_payload.get("description", ""),
        )
        return task.model_dump(mode="json")

    return mcp
