"""
aevum.sdk — Complication developer kit.

Usage:
    from aevum.sdk import Complication, Context
    from aevum.sdk.agent import AgentComplication

Register in pyproject.toml:
    [project.entry-points."aevum.complications"]
    my-comp = "my_package.complication:MyComplication"
"""

from aevum.sdk.agent import AgentComplication
from aevum.sdk.base import Complication, Context

__version__ = "0.1.0"

__all__ = ["Complication", "Context", "AgentComplication"]
