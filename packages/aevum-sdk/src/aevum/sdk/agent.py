"""
AgentComplication -- base class for autonomous agent complications.

Extends Complication with:
  - autonomy_level (L1-L5, DeepMind taxonomy, spec Section 12)
  - consecutive_actions counter (per-instance, thread-safe)
  - Automatic review trigger when threshold is exceeded

Usage:
    class MyAgent(AgentComplication):
        name = "my-agent"
        version = "0.1.0"
        capabilities = ["my-capability"]
        autonomy_level = 3  # L3: review every 5 consecutive actions

        async def run(self, ctx: Context, payload: dict) -> dict:
            # Do work
            return {"result": "done"}
            # after_run() is called automatically by the base class

Register in pyproject.toml:
    [project.entry-points."aevum.complications"]
    my-agent = "my_package.agent:MyAgent"
"""

from __future__ import annotations

import threading
from abc import abstractmethod
from collections.abc import Callable
from typing import Any, ClassVar

from aevum.sdk.base import Complication, Context

# Threshold: number of consecutive actions before review is triggered.
# None = never (L5 fully autonomous).
AUTONOMY_THRESHOLDS: dict[int, int | None] = {
    1: 1,   # L1: every action requires review
    2: 3,   # L2: review every 3 actions
    3: 5,   # L3: review every 5 actions
    4: 10,  # L4: review every 10 actions
    5: None,  # L5: fully autonomous, never triggers
}


class AgentComplication(Complication):
    """
    Base class for autonomous agent complications.

    Subclasses must define:
        name: str
        version: str
        capabilities: list[str]
        autonomy_level: int  (1-5)

    The Engine calls set_review_callback() at install time to inject
    the create_review function. Without this callback, the agent can
    still run -- it just cannot trigger reviews.
    """

    autonomy_level: ClassVar[int]

    def __init__(self) -> None:
        self._consecutive_actions: int = 0
        self._lock: threading.Lock = threading.Lock()
        self._review_callback: Callable[..., str] | None = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "autonomy_level"):
            level = cls.autonomy_level
            if not isinstance(level, int) or level not in range(1, 6):
                raise TypeError(
                    f"{cls.__name__}.autonomy_level must be an int from 1 to 5, got {level!r}"
                )

    def set_review_callback(self, callback: Callable[..., str]) -> None:
        """
        Injected by Engine.install_complication(). Provides access to
        Engine.create_review() without creating a circular dependency.
        """
        self._review_callback = callback

    def reset_consecutive_actions(self) -> None:
        """Called by Engine after a review is resolved (approve or veto)."""
        with self._lock:
            self._consecutive_actions = 0

    @property
    def consecutive_actions(self) -> int:
        with self._lock:
            return self._consecutive_actions

    async def run(
        self, ctx: Context | dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Subclasses implement _run() not run().
        run() wraps _run() with the autonomy threshold check.
        """
        result = await self._run(ctx, payload)
        await self._after_run(ctx)
        return result

    @abstractmethod
    async def _run(
        self, ctx: Context | dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Implement agent logic here (not in run())."""

    async def _after_run(self, ctx: Context | dict[str, Any]) -> None:
        """
        Increment counter and trigger review if threshold exceeded.
        Called automatically after every _run() invocation.
        """
        with self._lock:
            self._consecutive_actions += 1
            current = self._consecutive_actions

        threshold = AUTONOMY_THRESHOLDS.get(self.autonomy_level)
        if threshold is None:
            return  # L5: never triggers

        if current == threshold and self._review_callback is not None:
            actor = (
                ctx.actor if hasattr(ctx, "actor") else
                ctx.get("actor", "aevum-agent") if isinstance(ctx, dict) else
                "aevum-agent"
            )
            self._review_callback(
                proposed_action=f"Agent {self.name!r} has taken {current} consecutive actions",
                reason=(
                    f"Autonomy L{self.autonomy_level} threshold ({threshold}) reached. "
                    "Human review required before agent may continue."
                ),
                actor=actor,
                autonomy_level=self.autonomy_level,
                risk_assessment=f"Agent exceeded L{self.autonomy_level} consecutive action threshold",
            )

    def manifest(self) -> dict[str, Any]:
        """Extended manifest with autonomy_level."""
        base: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "description": getattr(self, "description", f"Agent complication: {self.name}"),
            "capabilities": list(self.capabilities),
            "classification_max": 0,
            "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
            "agent": {
                "autonomy_level": self.autonomy_level,
                "consecutive_action_threshold": AUTONOMY_THRESHOLDS.get(self.autonomy_level),
            },
        }
        return base
