---
description: "Migrate from the deprecated aevum-llm package to aevum-core adapters."
---

# Migrate from aevum-llm

`aevum-llm` was deprecated in v0.5.0 and will not receive further updates.
This guide shows how to replace it with the purpose-built adapters in
`aevum-core`.

---

## Why it was deprecated

`aevum-llm` was a thin wrapper that bundled provider-specific integration code
into a single package. As each integration grew in complexity — Cedar
evaluation, snapshot testing, GDPR erasure hooks — maintaining them in a
shared package became impractical. Each adapter now lives directly in
`aevum-core` with its own test suite and CI coverage.

See the [v0.5.0 section of CHANGELOG.md](https://github.com/aevum-labs/aevum/blob/main/CHANGELOG.md)
for the original deprecation notice.

---

## Step 1 — Uninstall aevum-llm

```bash
pip uninstall aevum-llm
```

---

## Adapter migration table

| Use case | New package extra | New import path |
|---|---|---|
| Anthropic Claude | `aevum-core[anthropic]` | `aevum.core.adapters.anthropic_adapter.AevumAnthropicAdapter` |
| LangChain | `aevum-core[langchain]` | `aevum.core.adapters.langchain_callback.AevumLangChainCallback` |
| LangGraph | `aevum-core[langgraph]` | `aevum.core.adapters.langgraph.AevumCheckpointer` |
| OpenAI Agents | `aevum-core[openai-agents]` | `aevum.core.adapters.openai_agents.AevumAgentHooks` |
| CrewAI | `aevum-core[crewai]` | `aevum.core.adapters.crewai.AevumCrewHooks` |

---

## Migration by adapter

### Anthropic

```bash
pip install "aevum-core[anthropic]"
```

```python
import anthropic
from aevum.core.adapters.anthropic_adapter import AevumAnthropicAdapter

client = AevumAnthropicAdapter(client=anthropic.Anthropic(), kernel=engine)
message = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

W3C traceparent is injected on every call. `tool_use` blocks are
Cedar-evaluated before your code sees them.
See the [Anthropic adapter guide](/learn/guides/anthropic/) for full details.

---

### LangChain

```bash
pip install "aevum-core[langchain]"
```

```python
from aevum.core.adapters.langchain_callback import AevumLangChainCallback
from langchain_openai import ChatOpenAI

cb = AevumLangChainCallback(kernel=engine)
llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[cb])
```

Tool calls are Cedar-evaluated on `on_tool_start`. LLM invocations are
recorded to the sigchain on `on_llm_start` and `on_llm_end`.
See the [LangChain guide](/learn/guides/langchain/) for full details including
LangGraph StateGraph usage.

---

### LangGraph

```bash
pip install "aevum-core[langgraph]"
```

```python
from aevum.core.adapters.langgraph import AevumCheckpointer

checkpointer = AevumCheckpointer.local()
graph = builder.compile(checkpointer=checkpointer)
config = {"configurable": {"thread_id": "alice-session-1"}}
result = graph.invoke(inputs, config)
```

Every superstep is signed (Ed25519 by default; optional ML-DSA-65 post-quantum dual signing) and chained.
`delete_thread("alice-session-1")` triggers GDPR Art. 17 crypto-erasure.

---

### OpenAI Agents

```bash
pip install "aevum-core[openai-agents]"
```

```python
from aevum.core.adapters.openai_agents import AevumAgentHooks

hooks = AevumAgentHooks(kernel=engine)
# Pass hooks= to your OpenAI Agents SDK Runner
```

---

### CrewAI

```bash
pip install "aevum-core[crewai]"
```

```python
from aevum.core.adapters.crewai import AevumCrewHooks, AevumTaskCallback

hooks = AevumCrewHooks(kernel=engine)
```

---

## After migration

Verify sigchain integrity to confirm the migration did not introduce gaps:

```python
assert engine.verify_sigchain()
```

If you previously recorded capture gaps in `aevum-llm`, those events are
preserved in the sigchain and remain replayable.
