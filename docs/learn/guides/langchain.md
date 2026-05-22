---
description: "Integrating Aevum with LangChain — governed memory, consent-checked context, and auditable chains."
---

# LangChain Integration Guide

This guide shows how to integrate Aevum with LangChain so that every LLM
invocation has a governed, consent-checked, sigchain-backed context.

---

## What we are building

A LangChain chain that:

1. Reads user context from Aevum (consent-verified)
2. Passes context to an LLM prompt
3. Records the LLM decision back into Aevum (signed, chained)
4. Enables deterministic replay of the exact decision for any past run

---

## Prerequisites

```bash
pip install aevum-core langchain-core langchain-openai
# OR: pip install aevum-core langchain-core langchain-anthropic
```

For Cedar policy enforcement:

```bash
pip install "aevum-core[cedar]"
```

---

## Environment setup

```bash
export OPENAI_API_KEY=sk-...       # or ANTHROPIC_API_KEY for Claude
export AEVUM_DEV=1                 # for local development only
```

---

## Complete example

```python
"""
Aevum + LangChain integration.

Demonstrates: governed context retrieval → LLM invocation → auditable commit.
"""
import os
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI   # or: from langchain_anthropic import ChatAnthropic

from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

# ── Aevum setup ───────────────────────────────────────────────────────────────
engine = Engine()  # AEVUM_DEV=1 if set; otherwise configure grants below

if not os.environ.get("AEVUM_DEV"):
    engine.add_consent_grant(ConsentGrant(
        grant_id="grant-alice-support",
        subject_id="alice",
        grantee_id="support-llm",
        operations=["ingest", "query"],
        purpose="support-resolution",
        classification_max=0,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2027-01-01T00:00:00Z",
    ))

# ── Ingest user context ───────────────────────────────────────────────────────
ingest_result = engine.ingest(
    data={"issue": "Cannot log in", "plan": "Pro", "tenure_years": 3},
    provenance={
        "source_id": "crm-system",
        "chain_of_custody": ["crm-system"],
        "classification": 0,
    },
    purpose="support-resolution",
    subject_id="alice",
    actor="support-llm",
)
audit_id = ingest_result.audit_id
print(f"Ingested context — audit_id: {audit_id}")

# ── Query for LLM context ─────────────────────────────────────────────────────
ctx = engine.query(
    purpose="support-resolution",
    subject_ids=["alice"],
    actor="support-llm",
)
alice_data = ctx.data["results"].get("alice", {})

# ── Build LangChain prompt ────────────────────────────────────────────────────
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful support agent. Use only the provided context."),
    ("human", "User context: {context}\n\nUser question: {question}"),
])

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
chain = prompt | llm | StrOutputParser()

response = chain.invoke({
    "context": str(alice_data),
    "question": "Why can't I log in to the portal?",
})
print(f"LLM response: {response}")

# ── Record the decision (commit) ──────────────────────────────────────────────
# commit() writes the LLM decision to the episodic ledger — signed, chained.
# This creates a verifiable record of: what context was used, what the LLM said.
decision_result = engine.commit(
    event_type="llm.support.response",
    payload={
        "context_audit_id": audit_id,
        "model": "gpt-4o-mini",
        "question": "Why can't I log in to the portal?",
        "response": response,
    },
    actor="support-llm",
)
decision_audit_id = decision_result.audit_id
print(f"Decision recorded — audit_id: {decision_audit_id}")

# ── Replay the exact decision ─────────────────────────────────────────────────
# At any future time, replay() reconstructs the exact payload from this run.
# No inference. No summarisation. Deterministic from the sigchain.
replay = engine.replay(audit_id=decision_audit_id, actor="support-llm")
assert replay.data["replayed_payload"]["response"] == response
print("Replay verified — decision is deterministically reproducible")

# ── Verify sigchain ───────────────────────────────────────────────────────────
assert engine.verify_sigchain()
print("Sigchain intact")
```

---

## Declaring out-of-band LLM calls

If you call an LLM without using Aevum's context for a particular step,
declare the gap so auditors can see it:

```python
engine.record_capture_gap(
    gap_type="llm",
    actor="support-llm",
    reason="direct_api_call",
    model_hint="gpt-4o-mini",
    extra={"note": "Classification routing call — no user data"},
)
```

This writes a `capture.gap` event to the sigchain. An auditor can see:
"at this point, the operator declared an out-of-band LLM call was made."

---

## Using AEVUM_DEV=1 vs explicit consent

| Scenario | Approach |
|---|---|
| Local development, prototyping | `AEVUM_DEV=1` |
| Staging with real user data | Explicit consent grants |
| Production | Explicit grants + Cedar + persistent store |

Never commit `AEVUM_DEV=1` to a production configuration file.

---

## Capture gap pattern

When building LangChain chains, you often have intermediate steps that do not
need to be in the Aevum context. Use `record_capture_gap()` to keep the audit
trail complete without instrumenting every step:

```python
# Before a non-governed step
engine.record_capture_gap(
    gap_type="tool",
    actor="my-chain",
    reason="web_search_not_audited",
)
# ... your tool call ...
# Then ingest the result into Aevum
engine.ingest(data=search_result, ...)
```

---

---

## AevumLangChainCallback — governance via callbacks

For applications that use the LangChain callback system directly,
`AevumLangChainCallback` is a drop-in `BaseCallbackHandler` that applies
Aevum governance to every tool call and LLM invocation without wrapping the
chain manually.

```bash
pip install "aevum-core[langchain]"
```

```python
from langchain_openai import ChatOpenAI
from aevum.core.adapters.langchain_callback import AevumLangChainCallback

cb = AevumLangChainCallback(kernel=engine)
llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[cb])
```

### What the callback governs

| Hook | What it does |
|---|---|
| `on_tool_start` | Cedar ABAC evaluation — raises `PermissionError` if denied |
| `on_tool_end` | Sigchain commit: output hash recorded |
| `on_llm_start` | Sigchain commit: prompt hash recorded |
| `on_llm_end` | Sigchain commit: completion hash recorded |
| `on_chain_error` | Capture gap recorded with `reason='langchain_chain_error'` |

### LangGraph StateGraph

LangGraph propagates callbacks through StateGraph nodes when the callback
is passed via `RunnableConfig`. Pass it in the config dict:

```python
from aevum.core.adapters.langchain_callback import AevumLangChainCallback

cb = AevumLangChainCallback(kernel=engine)
config = {"callbacks": [cb]}
result = graph.invoke(inputs, config)
```

### Strict isinstance() compatibility

If your framework checks `isinstance(cb, BaseCallbackHandler)`, use the
mixin pattern:

```python
from langchain_core.callbacks import BaseCallbackHandler
from aevum.core.adapters.langchain_callback import AevumLangChainCallback

class MyCallback(AevumLangChainCallback, BaseCallbackHandler):
    pass

cb = MyCallback(kernel=engine)
```

`AevumLangChainCallback` intentionally does not subclass `BaseCallbackHandler`
directly, so `aevum-core` can be imported without `langchain-core` installed.

---

## Next steps

- [Dev to Production checklist](/learn/dev-to-production/)
- [Architecture](/learn/architecture/)
- [Pure Python guide](/learn/guides/pure-python/)
- [Anthropic adapter guide](/learn/guides/anthropic/)

!!! note "OpenAI Agents guide"
    An integration guide for OpenAI Agents SDK is planned for v0.7.0.
