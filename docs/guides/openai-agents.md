# OpenAI Agents SDK Integration

`AevumAgentHooks` adds Cedar policy evaluation and sigchain recording to every
tool call and agent handoff in an OpenAI Agents SDK run.

## What it captures

Every hook call is based on what `AevumAgentHooks` in
`packages/aevum-core/src/aevum/core/adapters/openai_agents.py` actually does:

| Event | Cedar check | Sigchain record | Fields captured |
|-------|-------------|-----------------|-----------------|
| Tool start (`on_tool_start`) | Yes — raises `PermissionError` on deny | Context dict returned | `tool_name`, `agent_name`, `input_hash` (SHA-256 of serialized input), `started_at`, `cedar_permitted` |
| Tool end (`on_tool_end`) | No | Yes (if kernel) | `output_hash` (SHA-256 of `str(output)[:500]`), `success` |
| Agent handoff (`on_handoff`) | No | Yes (if kernel) | `from_agent`, `to_agent` |

Cedar fail path: `on_tool_start` raises `PermissionError` — the tool is not called.
Sigchain writes are non-blocking; failures are logged as warnings, never propagated.

## Installation

```bash
pip install "aevum-core[openai-agents]"
```

Verify the SDK version before use:

```bash
python3 -c "import agents; print(agents.__version__)"
```

Target: `openai-agents>=0.0.12`. The hook interface varies by SDK version —
see the module docstring in `openai_agents.py` for version-specific notes.

## Minimal example

```python
from aevum.core.adapters.openai_agents import AevumAgentHooks

# kernel=None means no sigchain writes (dev/test mode).
# Pass an aevum.core.Engine instance to enable full recording.
hooks = AevumAgentHooks(kernel=None)

# Attach to a run:
# from agents import Runner
# result = await Runner.run(agent, input, hooks=hooks)

# Manual test — verify Cedar allow path:
ctx = hooks.on_tool_start(
    tool_name="web_search",
    tool_input={"query": "aevum audit"},
    agent_name="research-agent",
)
print(ctx["cedar_permitted"])   # True
print(ctx["input_hash"][:8])    # first 8 chars of SHA-256

# Simulate tool end:
hooks.on_tool_end(ctx, tool_output="result text", success=True)

# Simulate handoff:
hooks.on_handoff(from_agent="research-agent", to_agent="summary-agent")
```

If the SDK requires subclassing:

```python
from agents import AgentHooks
from aevum.core.adapters.openai_agents import AevumAgentHooks

class MyHooks(AevumAgentHooks, AgentHooks):
    pass

hooks = MyHooks(kernel=kernel)
```

## What gets recorded

| `on_tool_start` context dict field | Description |
|------------------------------------|-------------|
| `tool_name` | Name of the tool being called |
| `agent_name` | Agent that owns the call (default: `"agent"`) |
| `input_hash` | SHA-256 of `str(tool_input or {})` |
| `started_at` | UTC ISO-8601 timestamp |
| `cedar_permitted` | Always `True` (exception raised on deny) |

| `on_tool_end` records | Description |
|-----------------------|-------------|
| `output_hash` | SHA-256 of `str(tool_output)[:500]` |
| `success` | Boolean outcome from caller |

## Verifying the audit trail

```bash
# Verify receipt integrity:
aevum verify-receipt <receipt_file>

# Verify by hash:
aevum verify-receipt --hash <receipt_hash>
```

## Configuration

`AevumAgentHooks` accepts one constructor argument:

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `kernel` | `Engine \| None` | `None` | Aevum kernel instance; if `None`, sigchain writes are skipped |

Input types are validated with Pydantic `TypeAdapter` at the adapter boundary.
Passing wrong types raises `TypeError` with a descriptive message.

## Full example

A complete, runnable example that creates a kernel, attaches governance hooks,
and exercises every hook path without making any OpenAI API calls:

```python
from aevum.core.engine import Engine
from aevum.core.adapters.openai_agents import AevumAgentHooks

# Create the Aevum kernel (in-memory; use oxigraph/postgres for persistence)
engine = Engine()

# Attach AevumAgentHooks — Cedar evaluation + sigchain recording enabled
hooks = AevumAgentHooks(kernel=engine)

# Governed tool call: Cedar is consulted before the tool executes
ctx = hooks.on_tool_start(
    tool_name="web_search",
    tool_input={"query": "aevum governance"},
    agent_name="research-agent",
)
assert ctx["cedar_permitted"] is True
# SHA-256 of the serialized input is recorded for provenance
print("Input hash:", ctx["input_hash"][:16])

# Record the tool result in the sigchain
hooks.on_tool_end(ctx, tool_output="Result: aevum provides sigchain governance", success=True)

# Agent hands off control: recorded as a sigchain entry
hooks.on_handoff(from_agent="research-agent", to_agent="summary-agent")

# Inspect the kernel state
print("Ledger entries:", engine.ledger_count())
```

The `docs/examples/test_openai_agents_guide.py` file covers this snippet with
pytest to confirm it stays importable and runnable across releases.

## Inline-snapshot drift detection

`tests/adapters/test_openai_agents_adapter.py` uses inline snapshots to guard
against silent behavioral changes in hook output. If the Cedar policy
configuration or sigchain payload format changes, these tests will fail
before the change reaches production.

## Next steps

- [MCP Integration](mcp.md) — expose Aevum governance to Claude Code, Cursor,
  and Windsurf via the `aevum-mcp` server
- [CLI Reference](../reference/cli.md) — `aevum verify` and `aevum verify-receipt`
  commands for sigchain inspection
- [Compliance Mapping](../learn/compliance-mapping.md) — how `AevumAgentHooks`
  satisfies EU AI Act Article 12 and Colorado SB 205 logging requirements
