"""
Aevum MCP server — five functions as MCP tools.

Each tool maps directly to the corresponding Engine method.
All tools are synchronous wrappers (Engine is sync; no asyncio bridge needed).
"""

from __future__ import annotations

from typing import Any

from aevum.core.engine import Engine

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

    return mcp
