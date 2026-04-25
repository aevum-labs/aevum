"""
aevum.sdk — Complication developer kit.

Usage:
    from aevum.sdk import Complication, Context

    class MyComplication(Complication):
        name = "my-comp"
        version = "0.1.0"
        capabilities = ["my-capability"]

        async def run(self, ctx: Context, payload: dict) -> dict:
            return {"result": "done"}

Register in pyproject.toml:
    [project.entry-points."aevum.complications"]
    my-comp = "my_package.complication:MyComplication"
"""

from aevum.sdk.base import Complication, Context

__version__ = "0.1.0"

__all__ = ["Complication", "Context"]
