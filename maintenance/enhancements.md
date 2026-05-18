# Aevum Enhancement Backlog

Proposals accumulate here across monthly Research sessions.
Claude Code updates this file during each execution session —
moving items between sections as they progress.

---

## Now  *(approved, next session)*

<!-- Claude Code: move items here when you set priority to NOW -->

---

## Soon  *(next 1–2 months)*

<!-- Claude Code: move items here from Research Report SOON proposals -->

---

## Backlog  *(good ideas, not yet prioritized)*

### aevum-maintainer Phase 1 completion — OIDC ingest + Cedar policies
- **Why:** Phase 1 scaffold exists but OIDC-verified ingest endpoint and Cedar policies for principal scoping are missing; self-governance pipeline cannot run end-to-end without them
- **Package:** aevum-maintainer
- **Scope:** M
- **Phases:** Phase 1a: add `POST /v1/ingest/scan-results` with OIDC token verification; Phase 1b: add Cedar policies scoping `github_actions` principal to ingest-only
- **Proposed:** 2026-05 Track A audit
- **Status:** Backlog

### aevum-maintainer Phase 2 — MCP research interface (6 read-only tools)
- **Why:** Research agent (Claude) needs Cedar-gated sigchain query tools to produce the Research Report; without them the maintenance workflow cannot advance past Phase 1
- **Package:** aevum-maintainer, aevum-mcp
- **Scope:** M
- **Phases:** Phase 2a: define 6 read-only MCP tools (list_sessions, get_session, list_entries, get_entry, search_entries, get_stats); Phase 2b: Cedar policy gating `research_agent` to query-only; Phase 2c: every query logged as sigchain entry
- **Proposed:** 2026-05 Track A audit
- **Status:** Backlog

### aevum-maintainer Phase 3 completion — A2A v1.0 task issuance
- **Why:** Structured consent gate is implemented (Phase 3 partial); A2A task issuance with embedded consent receipt hash is missing, blocking the execution agent step
- **Package:** aevum-maintainer, aevum-agent
- **Scope:** M
- **Phases:** Phase 3a: add `POST /v1/task/issue` that embeds consent receipt hash in A2A DataPart; Phase 3b: add `verify-task` CLI that checks hash against sigchain before executing
- **Proposed:** 2026-05 Track A audit
- **Status:** Backlog

### aevum-maintainer Phase 4 — Replay endpoint + Rekor anchor + break-glass
- **Why:** Auditors need `GET /v1/replay/{session_id}` for cryptographic session reconstruction; Rekor anchoring provides third-party tamper evidence; break-glass path required before any production use
- **Package:** aevum-maintainer, aevum-publish
- **Scope:** L
- **Phases:** Phase 4a: replay endpoint using engine.replay(); Phase 4b: weekly Rekor anchor workflow (`rekor-anchor.yml`); Phase 4c: break-glass CLI + `break_glass_log.jsonl`; Phase 4d: Article 12 compliance report endpoint
- **Proposed:** 2026-05 Track A audit
- **Status:** Backlog

### aevum-maintainer Phase 5 — Demo page (demo.aevum.build)
- **Why:** Public demonstration of the self-governance pipeline; referenced in README and self-governance docs but not deployed
- **Package:** aevum-maintainer (demo/)
- **Scope:** L
- **Phases:** Phase 5a: deploy maintainer server to Fly.io; Phase 5b: interactive sigchain explorer; Phase 5c: replay sandbox; Phase 5d: Article 12 compliance report export tab
- **Proposed:** 2026-05 Track A audit
- **Status:** Backlog

---

## Completed

<!-- Claude Code: move finished items here with version number -->

---

## Format for each entry

```
### [What]
- **Why:** [driver — protocol / compliance / competitive]
- **Package:** [which package(s)]
- **Scope:** [S / M / L]
- **Phases:** [for M/L — one line per phase]
- **Proposed:** [YYYY-MM Research Report]
- **Status:** [Now / Soon / Backlog / In Progress (phase N of M) / Done (vX.Y.Z)]
```
