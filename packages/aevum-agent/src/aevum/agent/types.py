# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
A2A v1.0 types — Linux Foundation ratified specification (April 2026).

BREAKING CHANGES from v1.0.0-rc:
  - Enums: SCREAMING_SNAKE_CASE (TaskStatus.SUBMITTED not "submitted")
  - No `kind` discriminator field on any type
  - JSON member-based polymorphism (discriminate by field presence)
  - Signed Agent Cards (JWS/RFC 7515)
  - OAuth 2.0 device-code flow (RFC 8628) + PKCE

A2A task lifecycle:
  SUBMITTED → RUNNING → COMPLETED
                      → FAILED
                      → CANCELLED

Standing Rule 17 confirmed: SCREAMING_SNAKE_CASE enums throughout.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import StrEnum
from typing import Any


class TaskStatus(StrEnum):
    """
    A2A v1.0 task status codes.
    SCREAMING_SNAKE_CASE per A2A v1.0 ratified spec (Rule 17).
    Breaking change from rc which used lower-case strings.
    """
    SUBMITTED  = "SUBMITTED"
    RUNNING    = "RUNNING"
    COMPLETED  = "COMPLETED"
    FAILED     = "FAILED"
    CANCELLED  = "CANCELLED"


class AgentCapability(StrEnum):
    """Capabilities an agent can advertise in its AgentCard."""
    STREAMING                = "STREAMING"
    PUSH_NOTIFICATIONS       = "PUSH_NOTIFICATIONS"
    STATE_TRANSITION_HISTORY = "STATE_TRANSITION_HISTORY"


@dataclasses.dataclass(frozen=True)
class A2ATask:
    """
    A2A v1.0 Task — the unit of work between agents.
    No `kind` discriminator field (removed in v1.0).
    """
    id: str
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    input: dict[str, Any]
    output: dict[str, Any] | None
    error: str | None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to A2A v1.0 wire format (no `kind` field)."""
        d: dict[str, Any] = {
            "id": self.id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "input": self.input,
        }
        if self.output is not None:
            d["output"] = self.output
        if self.error is not None:
            d["error"] = self.error
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclasses.dataclass(frozen=True)
class AgentCard:
    """
    A2A v1.0 AgentCard — describes an agent's identity and capabilities.
    Published at /.well-known/agent.json.
    Can be signed (JWS/RFC 7515) by the Aevum interceptor.
    """
    name: str
    description: str
    version: str
    url: str
    capabilities: tuple[AgentCapability, ...]
    skills: tuple[str, ...]
    authentication: dict[str, Any] = dataclasses.field(default_factory=dict)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to A2A v1.0 agent card format."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "url": self.url,
            "capabilities": [c.value for c in self.capabilities],
            "skills": list(self.skills),
            "authentication": self.authentication,
            "metadata": self.metadata,
        }
