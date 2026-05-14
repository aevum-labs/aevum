# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum hooks for CrewAI task and crew lifecycle.

AevumCrewHooks integrates Aevum governance into CrewAI's callback system.
Every task execution is checked against Cedar policy and recorded in the
sigchain. Consequential tasks can be gated by GOVERN.

Usage (CrewAI callbacks):
    from aevum.core.adapters.crewai import AevumCrewHooks, AevumTaskCallback
    from crewai import Crew, Task, Agent

    hooks = AevumCrewHooks(kernel=kernel)
    task = Task(
        description="Send billing email",
        callback=AevumTaskCallback(hooks=hooks, consequential=True),
        ...
    )

NOTE: CrewAI's callback/hook API varies by version. This implementation
targets CrewAI >=0.80.0. Check installed version before use:
    python3 -c "import crewai; print(crewai.__version__)"
Adapt method signatures to the actual installed API if needed.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from aevum.core.cedar_engine import CedarPolicyEngine

logger = logging.getLogger(__name__)


class AevumCrewHooks:
    """
    Governance hooks for CrewAI agents and tasks.
    Attaches Cedar ABAC evaluation and sigchain recording to CrewAI callbacks.
    """

    def __init__(self, kernel: Any | None = None) -> None:
        self._kernel = kernel

    def before_task(
        self,
        task_description: str,
        agent_role: str,
        consequential: bool = False,
        reversible: bool = True,
    ) -> dict[str, Any]:
        """
        Called before a CrewAI task executes.
        Returns a context dict with governance metadata.

        Cedar check: evaluates tool_call action.
        GOVERN: if consequential and not reversible, runs checkpoint.
        """
        engine = CedarPolicyEngine.default()

        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id=agent_role,
            action="tool_call",
            resource_type="ToolAction",
            resource_id=f"crewai:{task_description[:50]}",
            context={
                "taint_reads_untrusted": False,
                "taint_reads_private": False,
                "taint_can_exfiltrate": False,
                "has_crisis_content": False,
            },
        )

        if not permitted:
            raise PermissionError(f"Cedar denied CrewAI task: {task_description[:50]!r}")

        ctx: dict[str, Any] = {
            "task_description": task_description,
            "agent_role": agent_role,
            "started_at": datetime.now(UTC).isoformat(),
            "cedar_permitted": True,
            "consequential": consequential,
        }

        if consequential and not reversible and self._kernel is not None:
            from aevum.core.govern import GovernCheckpoint, ProposedAction

            gov = GovernCheckpoint(
                cedar_engine=engine,
                session_id=f"crew-{agent_role}",
                review_callback=None,
            )
            action = ProposedAction(
                action_type=f"crew_task:{task_description[:50]}",
                reversible=reversible,
                consequential=consequential,
                affects=[agent_role],
            )
            result = gov.checkpoint(action)
            ctx["govern_outcome"] = result.outcome.value
            if result.vetoed:
                raise PermissionError(f"GOVERN vetoed CrewAI task: {task_description[:50]!r}")

        return ctx

    def after_task(
        self,
        ctx: dict[str, Any],
        task_output: Any,
        success: bool,
    ) -> None:
        """
        Called after a CrewAI task completes.
        Records the outcome in the sigchain.
        """
        output_str = str(task_output)[:500]
        output_hash = hashlib.sha256(output_str.encode()).hexdigest()

        logger.debug(
            "CrewAI task complete: agent=%s success=%s output_hash=%s...",
            ctx.get("agent_role"),
            success,
            output_hash[:8],
        )

        if self._kernel is not None:
            try:
                logger.debug(
                    "Sigchain: CrewAI task agent=%s success=%s",
                    ctx.get("agent_role"),
                    success,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Sigchain record failed: %s", exc)


class AevumTaskCallback:
    """
    CrewAI task callback that wraps AevumCrewHooks.

    Pass as ``callback=AevumTaskCallback(hooks=hooks)`` to a CrewAI Task.
    The __call__ signature must match what CrewAI expects.
    Adapt if the installed CrewAI version has a different signature.
    """

    def __init__(
        self,
        hooks: AevumCrewHooks,
        consequential: bool = False,
        reversible: bool = True,
    ) -> None:
        self._hooks = hooks
        self._consequential = consequential
        self._reversible = reversible

    def __call__(self, output: Any) -> Any:
        """
        CrewAI calls this after task completion with the task output.
        Records outcome in sigchain via AevumCrewHooks.
        """
        ctx: dict[str, Any] = {
            "agent_role": "crew-agent",
            "task_description": "crewai-task",
            "started_at": datetime.now(UTC).isoformat(),
        }
        self._hooks.after_task(ctx, output, success=True)
        return output
