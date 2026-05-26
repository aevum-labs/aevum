# Google ADK Integration (AevumADKPlugin)

`AevumADKPlugin` integrates Aevum's Cedar policy engine and sigchain into the
Google Agent Development Kit (ADK) callback lifecycle. It is registered with
an ADK `Runner` via `plugins=[plugin]`.

## What it captures

Based on `packages/aevum-core/src/aevum/core/adapters/adk.py`,
verified against `google-adk 1.10.0`:

| Callback | Trigger | Cedar check | Sigchain record | Return value |
|----------|---------|-------------|-----------------|--------------|
| `before_tool_callback` | Before each tool execution | Yes | `tool.start` (if kernel) | Deny dict (blocks) or `None` (allows) |
| `after_tool_callback` | After each tool execution | No | `tool.end` (if kernel) | `None` (pass-through) |
| `before_model_callback` | Before each LLM API call | No | `llm_start` (debug log) | `None` (pass-through) |
| `after_model_callback` | After each LLM API call | No | `llm_end` (debug log) | `None` (pass-through) |

All callbacks are `async`.

Cedar deny path: `before_tool_callback` returns:
```python
{"error": "Aevum barrier denied tool: <tool_name>", "aevum_denied": True, "tool_name": "<tool_name>"}
```
ADK receives this dict instead of calling the tool. The tool is NOT executed.

Cedar fail-open: if Cedar evaluation raises an exception, the tool is allowed
and a warning is logged. This preserves availability under Cedar misconfiguration.

## Installation

```bash
pip install "aevum-core[adk]"
```

Requires `google-adk>=1.0.0`. Verified against `google-adk 1.10.0`.

## Minimal example

```python
from aevum.core.adapters.adk import AevumADKPlugin

# kernel=None: Cedar evaluation only, no sigchain writes.
# Pass an aevum.core.Engine instance to enable full recording.
plugin = AevumADKPlugin(kernel=None)

# Register with the ADK Runner via plugins=:
# from google.adk import Runner
# runner = Runner(
#     agent=my_agent,
#     app_name="my-app",
#     session_service=session_service,
#     plugins=[plugin],
# )

# With a kernel for full sigchain recording:
# from aevum.core import Engine
# kernel = Engine()
# plugin = AevumADKPlugin(kernel=kernel, name="aevum")
# runner = Runner(agent=my_agent, ..., plugins=[plugin])
```

## Parameter name contract

ADK dispatches callbacks by keyword. The parameter names in this file are
the contract — any mismatch causes `TypeError` at runtime.

| Callback | Required parameter names |
|----------|--------------------------|
| `before_tool_callback` | `tool`, `tool_args`, `tool_context` |
| `after_tool_callback` | `tool`, `tool_args`, `tool_context`, `result` |
| `before_model_callback` | `callback_context`, `llm_request` |
| `after_model_callback` | `callback_context`, `llm_response` |

Note: `after_tool_callback` uses `result` (not `tool_response`) — verified
against `google-adk 1.10.0 BasePlugin`.

All parameters are keyword-only (prefixed with `*` in the signature).

## Cedar context

`before_tool_callback` evaluates:

```
principal: AevumADKAgent / adk-agent
action:    tool_call
resource:  ToolAction / <tool_name>
context:   {args_hash: sha256(str(sorted(tool_args.items())))}
```

To scope policy to specific tools, write Cedar policies that match on
`resource.id`.

## AevumADKPlugin constructor

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `kernel` | `Engine \| None` | `None` | Aevum kernel; if `None`, sigchain writes are skipped |
| `name` | `str` | `"aevum"` | Plugin registry name; mirrors `BasePlugin.name` for ADK |

## Invariants satisfied

See `docs/architecture/invariants.md` for the full invariant list.
`AevumADKPlugin` satisfies:
- Consent as precondition: Cedar deny prevents tool execution
- Provenance as precondition: sigchain records tool identity and args hash
- Append-only audit: `kernel.record_event` writes are non-blocking and non-destructive
