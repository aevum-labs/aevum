# CrewAI Integration

`AevumCrewHooks` and `AevumTaskCallback` integrate Aevum governance into
CrewAI's task callback system. Every task execution is Cedar-evaluated and
recorded in the sigchain. Consequential, irreversible tasks can be gated by
a GOVERN checkpoint.

## What it captures

Based on `packages/aevum-core/src/aevum/core/adapters/crewai.py`:

| Event | Cedar check | GOVERN check | Sigchain record |
|-------|-------------|--------------|-----------------|
| `before_task()` | Yes — raises `PermissionError` on deny | Yes, if `consequential=True` and `reversible=False` | Context dict (in-memory) |
| `after_task()` | No | No | Yes (if kernel): `agent_role`, `success`, `output_hash` |
| `AevumTaskCallback.__call__()` | No | No | Yes via `after_task` |

Cedar resource ID format: `crewai:<task_description[:50]>`.

GOVERN path: if `consequential=True` and `reversible=False`, `before_task`
runs a `GovernCheckpoint`. If the checkpoint is vetoed, `PermissionError`
is raised and the task does not execute.

## Installation

```bash
pip install "aevum-core[crewai]"
```

Minimum version: `crewai>=0.80.0`. The callback and hook API changed
significantly in 0.80.0. Check installed version:

```bash
python3 -c "import crewai; print(crewai.__version__)"
```

## Minimal example

```python
from aevum.core.adapters.crewai import AevumCrewHooks, AevumTaskCallback

# kernel=None: Cedar evaluation only, no sigchain writes.
# Pass an aevum.core.Engine instance to enable full recording.
hooks = AevumCrewHooks(kernel=None)

# Attach to a CrewAI Task via callback:
# from crewai import Crew, Task, Agent
#
# task = Task(
#     description="Summarize the quarterly report",
#     callback=AevumTaskCallback(hooks=hooks, consequential=False),
#     agent=...,
# )
# crew = Crew(agents=[...], tasks=[task])
# crew.kickoff()

# For consequential, irreversible tasks — triggers GOVERN checkpoint:
# task = Task(
#     description="Send billing email to all customers",
#     callback=AevumTaskCallback(hooks=hooks, consequential=True, reversible=False),
#     agent=...,
# )

# Manual test — before_task:
ctx = hooks.before_task(
    task_description="Summarize the quarterly report",
    agent_role="analyst",
    consequential=False,
    reversible=True,
)
print(ctx["cedar_permitted"])   # True
print(ctx["consequential"])     # False

# Manual test — after_task:
hooks.after_task(ctx, task_output="Summary: ...", success=True)
```

## AevumTaskCallback

`AevumTaskCallback` wraps `AevumCrewHooks` in the callable interface
that CrewAI passes the task output to after completion:

```python
AevumTaskCallback(
    hooks=hooks,         # AevumCrewHooks instance
    consequential=False, # whether this task has consequential effects
    reversible=True,     # whether this task is reversible
)
```

CrewAI calls `callback(output)` after the task completes.
`AevumTaskCallback.__call__` calls `hooks.after_task()` and returns
the output unchanged.

`before_task` must be called separately before handing control to CrewAI
if you want Cedar pre-evaluation and optional GOVERN gating.

## crewai>=0.80.0 requirement

CrewAI's callback mechanism was redesigned in 0.80.0 to accept callables
directly on `Task(callback=...)`. Earlier versions used a different hook
attachment pattern. If you see `TypeError` or `AttributeError` on task
callback registration, verify the installed version.

## GOVERN checkpoint behavior

When `consequential=True` and `reversible=False`, `before_task` constructs
a `GovernCheckpoint` with `session_id=f"crew-{agent_role}"` and calls
`checkpoint(action)`. The `review_callback` is `None` by default — implement
and pass a callback to route the review to a human approval interface.
