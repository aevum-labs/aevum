# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
aevum-agent: A2A v1.0 agent protocol interceptor and governance layer.

Targets the Linux Foundation-ratified A2A v1.0 spec (April 2026):
  - SCREAMING_SNAKE_CASE enums (breaking change from rc)
  - OAuth 2.0 device-code flow (RFC 8628) + PKCE required
  - Signed Agent Cards (JWS/RFC 7515)
  - JSON member-based polymorphism (no kind discriminators)

Replaces the deprecated aevum-llm package.

Usage:
  from aevum.agent import AevumA2AInterceptor
  interceptor = AevumA2AInterceptor(kernel=kernel)
  signed_task = interceptor.create_task({"query": "hello"})
"""

from aevum.agent.interceptor import AevumA2AInterceptor, SignedAgentCard, SignedTask
from aevum.agent.types import A2ATask, AgentCapability, AgentCard, TaskStatus

__version__ = "0.8.0"
__all__ = [
    "A2ATask",
    "AgentCard",
    "TaskStatus",
    "AgentCapability",
    "AevumA2AInterceptor",
    "SignedTask",
    "SignedAgentCard",
]
