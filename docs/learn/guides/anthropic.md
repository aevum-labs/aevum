---
description: "Govern Anthropic Claude API calls with AevumAnthropicAdapter — traceparent injection, Cedar evaluation, and sigchain recording."
---

# Anthropic Adapter Guide

`AevumAnthropicAdapter` wraps the Anthropic Python SDK and applies Aevum
governance to every API call:

- W3C traceparent injected into every `messages.create()` request
- `tool_use` response blocks Cedar-evaluated before your code sees them
- Out-of-adapter SDK usage logged as a capture gap

---

## Install

```bash
pip install "aevum-core[anthropic]"
```

This installs `aevum-core` and `anthropic>=0.50.0`.

---

## Basic usage

```python
import anthropic
from aevum.core import Engine
from aevum.core.adapters.anthropic_adapter import AevumAnthropicAdapter

engine = Engine()  # AEVUM_DEV=1 for local dev; explicit grants for production

raw_client = anthropic.Anthropic()
client = AevumAnthropicAdapter(client=raw_client, kernel=engine)

message = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)
print(message.content[0].text)
```

Every call injects a W3C traceparent header. If the response contains
`tool_use` blocks, each block is Cedar-evaluated before being returned.

---

## Traceparent

The adapter generates a new W3C traceparent (`00-<trace_id>-<parent_id>-01`)
for each `messages.create()` call and injects it via `extra_headers`. The
trace ID is recorded in the Aevum sigchain for correlation with your OTel
backend.

Opt out with `AEVUM_SKIP_ANTHROPIC_TRACE=1` if you manage your own tracing.

---

## Tool use governance

When the model returns a `tool_use` block, the adapter Cedar-evaluates it
before returning the response:

```python
try:
    message = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Search for user data"}],
        tools=[{"name": "search_user_records", "description": "...", "input_schema": {...}}],
    )
except PermissionError as exc:
    # Cedar blocked the tool call — the sigchain records the denial
    print(f"Tool call blocked: {exc}")
```

---

## Capture gap detection

If your code uses `anthropic.Anthropic()` directly — bypassing the adapter —
the adapter logs a capture gap warning. Call `record_capture_gap()` explicitly
when you know you are using the raw SDK for a step the adapter does not cover:

```python
from aevum.core.adapters.anthropic_adapter import record_capture_gap

record_capture_gap(reason="streaming_not_supported")
# ... raw SDK streaming call ...
```

---

## Known limitations

The Anthropic SDK was migrated to a Stainless-generated client in early 2025.
The following are not wrapped in this version:

- `AsyncAnthropic` (async variant)
- `client.messages.stream()` (streaming)
- API namespaces other than `messages`

Re-evaluate when `anthropic` releases a `>=2.0` major version or changes the
`tool_use` block schema.

---

## Next steps

- [LangChain guide](/learn/guides/langchain/) — for chains and agents using the callback
- [MCP traceparent guide](/learn/guides/mcp/) — for MCP host integration
- [Dev to Production checklist](/learn/dev-to-production/)
