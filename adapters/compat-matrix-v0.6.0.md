# Aevum Adapter Compatibility Matrix — v0.6.0 Gate

**Captured:** 2026-05-20  
**Aevum version:** 0.5.0 → 0.6.0 (Phase A in progress)  
**Gate items:** G-17 through G-21; Phase A results appended  
**Unblocks:** Phase A adapter design  
**Phase A updated:** 2026-05-20

---

## Summary

| Adapter | Import Path | Class(es) | Min Version | CI Coverage | Status |
|---|---|---|---|---|---|
| LangGraph | `aevum.core.adapters.langgraph` | `AevumCheckpointer` | `langgraph-checkpoint>=4.1.0` | Snapshot tests, Py 3.11–3.13 ✓ | Tested (Phase A-1) |
| OpenAI Agents | `aevum.core.adapters.openai_agents` | `AevumAgentHooks` | `openai-agents>=0.0.12,<1.0` | Snapshot tests, Py 3.11–3.13 ✓ | Tested; canary live |
| CrewAI | `aevum.core.adapters.crewai` | `AevumCrewHooks`, `AevumTaskCallback` | `crewai>=0.80.0` | Snapshot tests, Py 3.11–3.13 ✓ | Tested (Phase A-1) |
| Anthropic SDK | `aevum.core.adapters.anthropic_adapter` | `AevumAnthropicAdapter` | `anthropic>=0.50.0` | Snapshot tests, Py 3.11–3.13 ✓ | Tested (Phase A-3) |
| LangChain | `aevum.core.adapters.langchain_callback` | `AevumLangChainCallback` | `langchain-core>=0.2.0` | Snapshot tests, Py 3.11–3.13 ✓ | Tested (Phase A-4) |
| A2A v1.0 | `aevum-agent` package | (see package) | A2A v1.0 ratified | Via aevum-maintainer tests | Tested |
| MCP | `aevum-mcp` package | (see package) | `fastmcp>=3.2.0` | aevum-mcp test suite; traceparent round-trip ✓ | Tested (Phase A-5) |
| SPIFFE | `aevum-spiffe` package | (see package) | SPIFFE JWT-SVID | aevum-spiffe test suite | Tested |

---

## G-17: LangGraph Adapter

**Import path:** `aevum.core.adapters.langgraph.AevumCheckpointer`  
**Extra:** `pip install "aevum-core[langgraph]"` → installs `langgraph-checkpoint>=4.1.0`  
**Status:** Loadable in isolation (no langgraph package required to import the class)  

**What it does:**
- Drop-in replacement for `MemorySaver`, `SQLiteSaver`, or `PostgresSaver`
- Every checkpoint dual-signed (Ed25519 + ML-DSA-65 if liboqs present) and RFC 3161 stamped
- `delete_thread()` → crypto-shredding (GDPR Art. 17 via consent ledger)
- Every superstep recorded in the Aevum sigchain

**CI status (Phase A-1):** ✅ Added to adapter-matrix.yml. Snapshot tests in
`test_langgraph_adapter.py` guard put/get_tuple shape, version sequence,
delete_thread erasure, and DEK shred contract.  
**Phase A result:** Gap closed.

---

## G-18: OpenAI Agents Adapter

**Import path:** `aevum.core.adapters.openai_agents.AevumAgentHooks`  
**Extra:** `pip install "aevum-core[openai-agents]"` → installs `openai-agents>=0.0.12`  
**CI version tested:** `openai-agents>=0.0.17` across Python 3.11, 3.12, 3.13  
**Status:** Tested — 4 snapshot tests guard against silent behavioral drift

**What it does:**
- Implements OpenAI Agents SDK hook interface for run lifecycle events
- Every tool call Cedar-evaluated before execution
- Agent handoffs recorded with full governance envelope

**Phase A-1/A-2 results:**
- ✅ Pin widened to `>=0.0.12,<1.0` in CI
- ✅ on_tool_end snapshot tests added
- ✅ Pydantic TypeAdapter boundary guards on on_tool_start/on_tool_end
- ✅ Nightly canary workflow live (`openai-agents-canary.yml`)
- ✅ Snapshot count: 4 → 8

---

## G-19: CrewAI Adapter

**Import path:** `aevum.core.adapters.crewai.AevumCrewHooks` and `AevumTaskCallback`  
**Extra:** `pip install "aevum-core[crewai]"` → installs `crewai>=0.80.0`  
**Status (Phase A-1):** ✅ Snapshot tests added; CI coverage live  

**What it does:**
- Hooks into CrewAI task and crew lifecycle callbacks
- Every task execution Cedar-evaluated and recorded in sigchain
- Consequential tasks can be gated by `review()`

**CI status (Phase A-1):** ✅ Added to adapter-matrix.yml. Snapshot tests in
`test_crewai_adapter.py` guard before_task shape, Cedar permit/deny,
and callback passthrough.  
**Phase A result:** Gap closed.

---

## G-20: A2A v1.0 Adapter (`aevum-agent`)

**Package:** `aevum-agent`  
**Protocol version:** A2A v1.0 ratified spec (migrated from v1.0.0-rc in v0.4.0)  
**Status:** Tested via `aevum-maintainer` tests (test_phase3_phase4.py)

**What it does:**
- A2A v1.0 protocol with sigchain-backed session records
- `aevum-maintainer` uses `issue_a2a_task()` to issue governed tasks after consent approval
- Task `correlation_id` is the sigchain `audit_id` — provides cryptographic trace from consent to execution

**Verification:** A2A task issuance tested end-to-end in `packages/aevum-maintainer/tests/test_phase3_phase4.py`.

---

## G-21: MCP Adapter (`aevum-mcp`)

**Package:** `aevum-mcp`  
**Dependency:** `fastmcp>=3.2.0` (CVE-2026-27124 / CVE-2025-64340 mitigated at this version)  
**Status:** Tested — aevum-mcp test suite

**What it does:**
- All five functions as MCP tools for any MCP-compatible host
- Governance middleware applied on every tool call

---

## Deprecated Adapter

**`aevum-llm`** — deprecated as of v0.5.0.  
Migration: use `aevum.core.adapters.langgraph`, `aevum.core.adapters.crewai`,
or `aevum.core.adapters.openai_agents` directly.  
`aevum-llm` will not receive further updates.  
A migration guide (DOC-XX) is scheduled for Phase DOC after Phase A adapters are complete.

---

## Python Version Matrix

| Python | NullPolicyEngine | CedarPolicyEngine | OpenAI Agents |
|---|---|---|---|
| 3.11 | CI ✓ | CI ✓ | CI ✓ |
| 3.12 | CI ✓ | CI ✓ | CI ✓ |
| 3.13 | CI ✓ | CI ✓ | CI ✓ |

LangGraph and CrewAI adapters: not tested against any Python version in CI.

---

## Policy Engine Compatibility

| Engine | Status | Use Case | Fail Behavior |
|---|---|---|---|
| `CedarPolicyEngine` | Optional extra (`[cedar]`) | Entity ABAC, barriers, taint | Fail-closed (no cedarpy → RuntimeError at init) |
| `NullPolicyEngine` | Built-in fallback | Dev/test; warns at first use | Fail-open with WARNING |
| `OPAPolicyEngine` | Built-in, no extra needed | Content policy (HIPAA, PCI) | Fail-open per ADR-005 |

**Key design finding (G-25):** Cedar and OPA serve different layers:
- Cedar (in-process, ~496µs per eval): entity ABAC — who can do what to which resource
- OPA (HTTP sidecar, 2s timeout): content/payload policy — minimum-necessary, scope rules
- The absolute barriers (barriers.py / barriers.cedar) are Cedar `forbid` policies and run unconditionally regardless of which PolicyEngine is configured

---

## Gaps Identified by Gate + Phase A Resolution

| Gap | Gate Status | Phase A Status |
|---|---|---|
| LangGraph CI coverage missing | ❌ Zero coverage | ✅ Closed (A-1) |
| CrewAI CI coverage missing | ❌ Zero coverage | ✅ Closed (A-1) |
| OpenAI Agents version range gap | ❌ CI only at >=0.0.17 | ✅ Closed — widened to >=0.0.12,<1.0 (A-1) |
| aevum-llm migration guide not written | ❌ Missing | ⏳ Scheduled for Phase DOC |
| OPA sidecar not tested in CI | ❌ Unit tests only | ⏳ Not in Phase A scope |
| Anthropic SDK adapter missing | ❌ Not implemented | ✅ Closed (A-3) |
| LangChain callback missing | ❌ Not implemented | ✅ Closed (A-4) |
| MCP traceparent not injected | ❌ No OTel tracing | ✅ Closed (A-5) |
| OpenClaw drift detection missing | ❌ Not implemented | ✅ Closed (A-6) |

---

## Phase A: New Adapters

### A-3: Anthropic SDK Adapter

**Import path:** `aevum.core.adapters.anthropic_adapter.AevumAnthropicAdapter`  
**Extra:** `pip install "aevum-core[anthropic]"` → installs `anthropic>=0.50.0`  
**CI coverage:** Snapshot tests, Py 3.11–3.13 ✅  

**What it does:**
- Wraps `anthropic.Anthropic`; intercepts `messages.create()`
- W3C traceparent injected via `extra_headers` on every API call
- `tool_use` response blocks Cedar-evaluated; PermissionError on deny
- `record_capture_gap()` logs WARNING when SDK used outside adapter
- `AEVUM_SKIP_ANTHROPIC_TRACE=1` opt-out

**Re-evaluate when:** `anthropic` releases a >=2.0 major version or changes
`tool_use` block schema.

---

### A-4: LangChain Governance Callback

**Import path:** `aevum.core.adapters.langchain_callback.AevumLangChainCallback`  
**Extra:** `pip install "aevum-core[langchain]"` → installs `langchain-core>=0.2.0`  
**CI coverage:** Snapshot tests, Py 3.11–3.13 ✅  

**What it does:**
- `on_tool_start` → Cedar ABAC evaluation → PermissionError on deny
- `on_tool_end`, `on_llm_start`, `on_llm_end` → sigchain commit
- `on_chain_error` → capture gap with `reason='langchain_chain_error'`
- Verified propagation through LangGraph StateGraph nodes
- Mixin pattern for strict `isinstance(cb, BaseCallbackHandler)` checks

**Re-evaluate when:** `langchain-core` releases a >=1.0 stable version or
renames hook methods.

---

### A-5: MCP Traceparent (G-17/G-18 confirmed)

**Module:** `aevum.mcp.traceparent`  
**OTel spec:** SEP-414 (draft) — `_meta.traceparent` / `_meta.tracestate` / `_meta.baggage`  
**CI coverage:** 24 round-trip integration tests ✅  

**What it does:**
- `inject_into_meta(params)`: injects W3C traceparent into MCP request `_meta`
- `extract_from_meta(params)`: extracts and validates incoming traceparent server-side
- `trace_id` recorded in sigchain via `_record_in_sigchain(trace_id=...)`
- `AEVUM_MCP_SKIP_TRACE_INJECT=1` opt-out
- Invalid traceparent format logged and rejected

**G-17/G-18 confirmed:** OTel traceparent round-trip tested through fastmcp mock.
