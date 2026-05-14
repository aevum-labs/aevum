# Quickstart

## Install

```bash
pip install aevum-core
```

## Initialize

```bash
aevum init
```

## Your first governed session

```python
import asyncio
from aevum.core.kernel import Kernel

async def main():
    kernel = Kernel.local()
    async with kernel.session(user="alice", purpose="support") as s:
        await s.relate("alice prefers dark mode", source="profile")
        ctx = await s.navigate("alice's preferences")
        print(ctx.agent_prompt)
        print(f"Uncertainty: {ctx.uncertainty:.0%}")

asyncio.run(main())
```

## LangGraph drop-in

```python
from aevum.core.adapters.langgraph import AevumCheckpointer

checkpointer = AevumCheckpointer.local()
graph = builder.compile(checkpointer=checkpointer)
config = {"configurable": {"thread_id": "alice-session-1"}}
result = graph.invoke(inputs, config)
# delete_thread → GDPR Art. 17 crypto-shredding
checkpointer.delete_thread("alice-session-1")
```

See [Getting Started](getting-started/quickstart.md) for the full guide.
