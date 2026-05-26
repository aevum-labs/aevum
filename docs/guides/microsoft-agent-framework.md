# Microsoft Agent Framework Integration (AevumMAFMiddleware)

Three middleware classes integrate Aevum governance into the Microsoft Agent
Framework (MAF) pipeline. A convenience factory, `AevumMAFMiddleware`, returns
all three as a list for direct use with `Agent(middleware=...)`.

## What it captures

Based on `packages/aevum-core/src/aevum/core/adapters/maf.py`,
verified against `agent-framework 1.6.0`:

| Class | MAF base | Trigger | Cedar check | Sigchain record |
|-------|----------|---------|-------------|-----------------|
| `AevumAgentMiddleware` | `AgentMiddleware` | Agent run start/end | No | `agent.start`, `agent.end` (if kernel) |
| `AevumFunctionMiddleware` | `FunctionMiddleware` | Every tool/function call | Yes | `tool.start`, `tool.end` (if kernel); raises `MiddlewareTermination` on deny |
| `AevumChatMiddleware` | `ChatMiddleware` | Every LLM API call | No | `llm.call` (if kernel) |

All `process(context, call_next)` methods are `async`.

MAF dispatches by `isinstance` — inheritance from the MAF base classes is
required (not duck typing). When `agent-framework` is not installed, the
module is importable but the base classes are replaced with no-op stubs.

### Deny path (AevumFunctionMiddleware)

On Cedar deny:
1. `context.result` is set to `{"error": "...", "aevum_denied": True, "tool_name": "<name>"}`
2. `MiddlewareTermination` is raised
3. `call_next` is NOT called — the tool/function does not execute

Cedar fail-open: if Cedar evaluation raises an exception, a warning is logged
and `call_next` is called (execution continues).

## Installation

```bash
pip install "aevum-core[maf]"
```

Requires `agent-framework>=1.0.0`. Verified against `agent-framework 1.6.0`.

**Note:** `agent-framework 1.6.0` installs approximately 159 transitive
dependencies, including the Azure SDK. Use a dedicated virtual environment
for MAF deployments to avoid version conflicts with other packages.

## Minimal example

```python
from aevum.core.adapters.maf import AevumMAFMiddleware

# kernel=None: Cedar evaluation only, no sigchain writes.
# Pass an aevum.core.Engine instance to enable full recording.

# from agent_framework import Agent
# from openai import AsyncAzureOpenAI
#
# client = AsyncAzureOpenAI(...)
# agent = Agent(
#     client=client,
#     name="assistant",
#     middleware=AevumMAFMiddleware(kernel=None),
# )

# AevumMAFMiddleware returns:
# [AevumAgentMiddleware(kernel), AevumFunctionMiddleware(kernel), AevumChatMiddleware(kernel)]
```

With a kernel for full sigchain recording:

```python
from aevum.core import Engine
from aevum.core.adapters.maf import AevumMAFMiddleware

kernel = Engine()

# from agent_framework import Agent
# agent = Agent(
#     client=client,
#     name="assistant",
#     middleware=AevumMAFMiddleware(kernel=kernel),
# )
```

## Using individual middleware classes

If you need only one middleware, import the class directly:

```python
from aevum.core.adapters.maf import (
    AevumAgentMiddleware,
    AevumFunctionMiddleware,
    AevumChatMiddleware,
)

# agent = Agent(
#     client=client,
#     middleware=[AevumFunctionMiddleware(kernel=kernel)],
# )
```

## Middleware order

`AevumMAFMiddleware` returns middleware in this order:
1. `AevumAgentMiddleware` — outermost, wraps the full agent run
2. `AevumFunctionMiddleware` — gates tool calls with Cedar
3. `AevumChatMiddleware` — innermost, observes raw LLM calls

## Cedar context (AevumFunctionMiddleware)

```
principal: AevumMAFAgent / maf-agent
action:    tool_call
resource:  ToolAction / <function.name>
context:   {args_hash: sha256(str(context.arguments))}
```

Tool name is sourced from `context.function.name`; if absent, `"unknown"` is used.

## Constructor reference

All three classes accept the same constructor:

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `kernel` | `Engine \| None` | `None` | Aevum kernel; if `None`, sigchain writes are skipped |
