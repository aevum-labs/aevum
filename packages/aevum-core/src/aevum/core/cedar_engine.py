# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Backward-compatibility re-export. Use aevum.core.policy.cedar_engine directly."""
from aevum.core.policy.cedar_engine import CedarPolicyEngine, PolicyError

__all__ = ["CedarPolicyEngine", "PolicyError"]
