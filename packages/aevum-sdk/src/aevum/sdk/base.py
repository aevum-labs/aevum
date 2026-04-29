"""
Complication and Context — the two classes every complication author needs.

Complication: subclass this, set class attributes, implement run().
Context: passed to run() — carries request state from the kernel.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Context:
    """
    Request context passed to Complication.run().

    Carries everything the complication needs to know about the current
    kernel operation without exposing the full Engine.
    """

    subject_ids: list[str]
    purpose: str
    actor: str
    classification_max: int = 0
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


class Complication(ABC):
    """
    Base class for all Aevum complications.

    Subclass this, set the three class attributes, implement run().
    Everything else (health, manifest, OTel) is automatic.

    Class attributes (all required):
        name: str           — unique identifier (kebab-case)
        version: str        — SemVer
        capabilities: list  — what this complication provides

    Example:
        class EchoComplication(Complication):
            name = "echo"
            version = "0.1.0"
            capabilities = ["echo"]

            async def run(self, ctx: Context, payload: dict) -> dict:
                return {"echoed": payload}
    """

    # Subclasses must define these
    name: ClassVar[str]
    version: ClassVar[str]
    capabilities: ClassVar[list[str]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Validate required class attributes at class definition time
        # Skip validation for abstract classes (those without name set)
        if hasattr(cls, "name") and hasattr(cls, "version") and hasattr(cls, "capabilities"):
            if not isinstance(cls.name, str) or not cls.name:
                raise TypeError(f"{cls.__name__}.name must be a non-empty string")
            if not isinstance(cls.version, str) or not cls.version:
                raise TypeError(f"{cls.__name__}.version must be a non-empty string")
            if not isinstance(cls.capabilities, list) or not cls.capabilities:
                raise TypeError(f"{cls.__name__}.capabilities must be a non-empty list")

    @abstractmethod
    async def run(self, ctx: Context, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Execute this complication for the given context and payload.

        Must not raise exceptions — return an error dict on failure:
            {"error": "description of what went wrong"}

        Must not modify ctx or payload.
        Must complete within the kernel's complication timeout.
        """

    def health(self) -> bool:
        """
        Return True if this complication is healthy and ready to serve.
        Override to add real health checks (database ping, API check, etc.).
        Default: always healthy.
        """
        return True

    def run_sync(self, ctx: Context, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Synchronous wrapper for run(). Useful for testing and simple integrations.
        """
        return asyncio.run(self.run(ctx, payload))

    def manifest(self) -> dict[str, Any]:
        """
        Generate the complication manifest from class attributes.

        Returns a dict conforming to the complication manifest schema (spec Section 11).
        Override this method to customise classification_max, functions, or auth.
        """
        return {
            "name": self.name,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "schema_version": "1.0",
            "health_endpoint": None,
            "classification_max": 0,
            "functions": ["query"],
            "auth": {
                "scopes_required": [],
                "public_key": None,
            },
        }
