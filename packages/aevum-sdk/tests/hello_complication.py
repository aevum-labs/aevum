"""
Hello-world complication — the Phase 5 gate example.
Used by tests. Also serves as the canonical reference implementation.
"""

from aevum.sdk import Complication, Context


class HelloComplication(Complication):
    name = "hello"
    version = "0.1.0"
    capabilities = ["echo"]

    async def run(self, ctx: Context, payload: dict) -> dict:  # type: ignore[type-arg]
        return {"result": f"hello, {payload.get('who', 'world')}"}
