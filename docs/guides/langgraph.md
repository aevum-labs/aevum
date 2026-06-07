# LangGraph Integration (AevumCheckpointer)

`AevumCheckpointer` is a drop-in replacement for LangGraph's built-in
checkpoint savers (`MemorySaver`, `SQLiteSaver`, `PostgresSaver`). It adds
dual-signing, GDPR Art. 17 crypto-shredding, and sigchain recording to every
LangGraph superstep.

## What it captures

Based on `packages/aevum-core/src/aevum/core/adapters/langgraph.py`:

| Event | Description |
|-------|-------------|
| Every `put()` call | LangGraph calls `put()` at the end of every superstep. AevumCheckpointer stores the checkpoint in SQLite and records `thread_id`, `checkpoint_id`, and `payload_hash` (SHA-256) in the sigchain. |
| `put_writes()` | Stores intermediate node writes within a superstep. Not separately sigchained — included in the parent checkpoint record. |
| `delete_thread()` | Deletes all checkpoint data for a thread AND crypto-shreds the subject's DEK via the consent ledger (GDPR Art. 17). The sigchain entries remain; the encrypted content becomes unreadable. |

## Installation

```bash
pip install "aevum-core[langgraph]"
```

Supported: `langgraph-checkpoint==4.1.*`. LangGraph ships breaking changes
quarterly — the conformance test suite in CI catches regressions. Pin to
`4.1.*` until you have verified compatibility with a newer version.

## Minimal example

```python
from aevum.core.adapters.langgraph import AevumCheckpointer

# Zero-config local mode: SQLite at ~/.aevum/checkpoints.db
checkpointer = AevumCheckpointer.local()

# Or with a custom path and kernel:
# from aevum.core import Engine
# kernel = Engine()
# checkpointer = AevumCheckpointer.local(kernel=kernel)

# Compile the graph with the checkpointer:
# from langgraph.graph import StateGraph
# builder = StateGraph(MyState)
# builder.add_node(...)
# graph = builder.compile(checkpointer=checkpointer)

# Run with a thread ID:
# config = {"configurable": {"thread_id": "alice-session-1"}}
# result = graph.invoke(inputs, config)
# Every superstep is signed and chained.

# GDPR Art. 17 erasure — crypto-shreds Alice's DEK:
# checkpointer.delete_thread("alice-session-1")

# Async graph (async/await):
# result = await graph.ainvoke(inputs, config)
# Async methods (aput, aput_writes, aget_tuple, alist, adelete_thread)
# delegate to sync via run_in_executor — no additional setup required.
```

## SQLite schema

AevumCheckpointer creates three tables on first use:

| Table | Key columns | Purpose |
|-------|-------------|---------|
| `checkpoints` | `thread_id`, `checkpoint_ns`, `checkpoint_id` | One row per superstep checkpoint |
| `checkpoint_writes` | `thread_id`, `checkpoint_ns`, `checkpoint_id`, `task_id`, `idx` | Intermediate node writes within a superstep |
| `checkpoint_versions` | `thread_id`, `checkpoint_ns`, `channel` | Per-channel version counters |

## LANGGRAPH_STRICT_MSGPACK

**Required** — set to `true` in all production deployments:

```bash
export LANGGRAPH_STRICT_MSGPACK=true
```

This causes LangGraph to reject non-serializable state values at checkpoint
time rather than silently coercing them. Without this flag, state that cannot
round-trip through msgpack may be stored in a lossy form, making replay
unreliable.

This flag also mitigates CVE-2025-64439 (CVSS 7.4) — RCE via
`JsonPlusSerializer` json-fallback constructor deserialization, fixed in
`langgraph-checkpoint>=3.0`. Enabling strict-mode msgpack prevents the unsafe
object construction path even if older serializer code is reached transitively.

## Version pinning

Pin `langgraph-checkpoint==4.1.*` in production `requirements.txt` or
`uv.lock`. LangGraph has shipped breaking changes to `BaseCheckpointSaver`
method signatures between minor versions. The CI conformance suite tests
`AevumCheckpointer` against the pinned version; upgrading without verifying
against the suite may break checkpoint storage silently.

## Optional class registration

If LangGraph performs `isinstance(checkpointer, BaseCheckpointSaver)` checks
at graph compilation time, call this once at startup:

```python
AevumCheckpointer.register_with_langgraph()
```

This injects `BaseCheckpointSaver` into `AevumCheckpointer.__bases__`. It
is only needed if compilation fails with an isinstance error — otherwise skip it.

## Constructor reference

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `db_path` | `Path` | — | SQLite file path (required for direct construction) |
| `kernel` | `Engine \| None` | `None` | Aevum kernel; if `None`, sigchain writes are skipped |

Use `AevumCheckpointer.local()` for zero-config SQLite at `~/.aevum/checkpoints.db`.
