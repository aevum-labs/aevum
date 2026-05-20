# Aevum Adapter Compatibility Matrix — v0.6.0 Gate

**Captured:** 2026-05-20  
**Aevum version:** 0.5.0  
**Gate items:** G-17 through G-21  
**Unblocks:** Phase A adapter design

---

## Summary

| Adapter | Import Path | Class(es) | Min Version | CI Coverage | Status |
|---|---|---|---|---|---|
| LangGraph | `aevum.core.adapters.langgraph` | `AevumCheckpointer` | `langgraph-checkpoint>=4.1.0` | None | Loadable; no CI |
| OpenAI Agents | `aevum.core.adapters.openai_agents` | `AevumAgentHooks` | `openai-agents>=0.0.12` | Snapshot tests, Py 3.11–3.13 | Tested |
| CrewAI | `aevum.core.adapters.crewai` | `AevumCrewHooks`, `AevumTaskCallback` | `crewai>=0.80.0` | None | Loadable; no CI |
| A2A v1.0 | `aevum-agent` package | (see package) | A2A v1.0 ratified | Via aevum-maintainer tests | Tested |
| MCP | `aevum-mcp` package | (see package) | `fastmcp>=3.2.0` | aevum-mcp test suite | Tested |
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

**CI status:** NOT in the adapter-matrix CI. Only openai-agents snapshot tests run in CI.  
**Gap:** No regression protection if `langgraph-checkpoint` API changes.  
**Phase A action:** Add langgraph to adapter-matrix.yml CI (oldest, latest, pre-release).

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

**Known issue:** SDK hook interface varies by version (documented in adapter source).
The adapter targets `openai-agents>=0.0.12` but was validated at `>=0.0.17`.
Versions 0.0.12–0.0.16 are not regression-tested.

**Phase A action:** Widen CI matrix to test oldest (0.0.12), latest, and pre-release.

---

## G-19: CrewAI Adapter

**Import path:** `aevum.core.adapters.crewai.AevumCrewHooks` and `AevumTaskCallback`  
**Extra:** `pip install "aevum-core[crewai]"` → installs `crewai>=0.80.0`  
**Status:** Loadable in isolation; no CI coverage  

**What it does:**
- Hooks into CrewAI task and crew lifecycle callbacks
- Every task execution Cedar-evaluated and recorded in sigchain
- Consequential tasks can be gated by `review()`

**CI status:** NOT in the adapter-matrix CI.  
**Gap:** No regression protection. CrewAI has a history of rapid API changes.  
**Phase A action:** Add CrewAI to adapter-matrix.yml CI; add snapshot tests.

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

## Gaps Identified by This Matrix

1. **LangGraph CI coverage missing** — highest priority for Phase A; `AevumCheckpointer` is the most widely used adapter but has zero regression protection
2. **CrewAI CI coverage missing** — CrewAI's rapid API evolution makes this high risk
3. **OpenAI Agents version range gap** — adapter declares `>=0.0.12` but CI only tests `>=0.0.17`
4. **aevum-llm migration guide not yet written** — blocks Phase DOC (scheduled after Phase A)
5. **OPA sidecar not tested in CI** — `OPAPolicyEngine` has unit tests but no integration test with a real OPA process
