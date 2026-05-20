# Aevum Enhancement Backlog

Proposals accumulate here across monthly Research sessions.
Claude Code updates this file during each execution session —
moving items between sections as they progress.

---

## Now  *(approved, next session)*

<!-- Claude Code: move items here when you set priority to NOW -->

---

## Soon  *(next 1–2 months)*

### aevum-maintainer Phase 4d — Article 12 compliance report endpoint
- **Why:** Auditors need a governed endpoint that renders EU AI Act Article 12
  compliance evidence sourced from the sigchain; phases 4a–4c shipped in v0.5.0
  but this sub-phase was not implemented
- **Package:** aevum-maintainer
- **Scope:** S
- **Phases:** Phase 4d: `GET /v1/compliance/article12` returning sigchain-sourced
  Article 12 evidence as JSON-LD; record each generation call in the sigchain via
  `engine.commit()`
- **Proposed:** 2026-05 Track A audit
- **Status:** Soon

### aevum-maintainer Phase 5a — Deploy maintainer server to Fly.io
- **Why:** Public demonstration of the self-governance pipeline requires a live
  deployment; `fly.toml` and `static/index.html` exist in v0.5.0; live deployment
  is the remaining step before demo.aevum.build is reachable
- **Package:** aevum-maintainer (demo/)
- **Scope:** S
- **Phases:** Phase 5a: deploy maintainer server to Fly.io using existing `fly.toml`;
  smoke-test `/health` endpoint; configure `AEVUM_BREAK_GLASS_TOKEN` secret in Fly
- **Proposed:** 2026-05 Track A audit
- **Status:** Soon

---

## Backlog  *(good ideas, not yet prioritized)*

### aevum-maintainer Phase 2 (completion) — Cedar principal gating + query logging
- **Why:** Phase 2a (six read-only MCP tools) shipped in v0.5.0 but was not noted
  in the CHANGELOG; Phase 2b (Cedar policy scoping `research_agent` principal to
  query-only) and Phase 2c (sigchain logging of every query) were not implemented
- **Package:** aevum-maintainer, aevum-mcp
- **Scope:** S
- **Phases:** Phase 2b: `policies/research_agent.cedar` permitting
  `AevumAgent::"research_agent"` on `Action::"query"` only; Phase 2c: each
  `mcp_tools.*` call commits a `mcp.query_executed` event to the sigchain so
  research sessions are auditable
- **Proposed:** 2026-05 Track A audit
- **Status:** In Progress (Phase 2a of 3 complete — 6 tools built, tested, and
  integrated in `server.py`; Phase 2b Cedar policy and Phase 2c sigchain logging
  remain; deferred to v0.6.0 cycle)

### aevum-maintainer Phase 5 (5b–5d) — Interactive demo features
- **Why:** Interactive self-governance demo deferred from v0.5.0; Phase 5a
  (deployment) moves to Soon; remaining features target v0.7.0 once the server
  has been live long enough to inform the UX
- **Package:** aevum-maintainer (demo/)
- **Scope:** M
- **Phases:** Phase 5b: interactive sigchain explorer (paginated entry browser);
  Phase 5c: replay sandbox (submit an audit_id, view reconstructed state);
  Phase 5d: Article 12 compliance report export tab (UI wrapper for Phase 4d)
- **Proposed:** 2026-05 Track A audit
- **Status:** Backlog (v0.7.0)

---

## Completed

### aevum-maintainer Phase 1 — OIDC ingest + Cedar policies
- **Why:** OIDC-verified ingest endpoint and Cedar policies for principal scoping
  required before the self-governance pipeline can run end-to-end
- **Package:** aevum-maintainer
- **Scope:** M
- **Phases:** Phase 1a: `POST /v1/ingest/scan-results` with OIDC token verification
  against GitHub Actions JWKS; Phase 1b: `policies/scan_ingest.cedar` scoping
  `AevumAgent::"github-actions"` to `Action::"relate_graph_write"` with active
  consent and purpose-match guards
- **Proposed:** 2026-05 Track A audit
- **Status:** Done (v0.5.0) — verified in `server.py` and `scan_ingest.cedar`

### aevum-maintainer Phase 3 — A2A v1.0 task issuance
- **Why:** A2A task issuance with embedded consent receipt hash is required for
  the execution agent step of the maintenance pipeline
- **Package:** aevum-maintainer, aevum-agent
- **Scope:** M
- **Phases:** Phase 3a: `issue_a2a_task()` in `a2a_tasks.py` embeds consent receipt
  audit_id as `correlation_id` in the A2A task body; invoked from `/v1/consent/approve`
  when `AEVUM_AGENT_URL` is set; note — standalone `verify-task` CLI (Phase 3b) was
  not implemented; the consent hash is carried in the A2A `metadata` field instead
- **Proposed:** 2026-05 Track A audit
- **Status:** Done (v0.5.0) — verified in `a2a_tasks.py` and `test_phase3_phase4.py`

### aevum-maintainer Phase 4 (4a–4c) — Replay endpoint + Rekor anchor + break-glass
- **Why:** Auditors need cryptographic session reconstruction; Rekor anchoring
  provides third-party tamper evidence; break-glass path required before production use
- **Package:** aevum-maintainer, aevum-publish
- **Scope:** L
- **Phases:** Phase 4a: `POST /v1/replay/{audit_id}` using `engine.replay()`;
  Phase 4b: `_try_anchor_sigchain()` called on every consent approval (advisory,
  inline — no weekly rekor-anchor.yml workflow; advisory anchor is the shipped form);
  Phase 4c: `POST /v1/break-glass` with HMAC token verification and mandatory
  sigchain recording at classification=3; Phase 4d moved to Soon
- **Proposed:** 2026-05 Track A audit
- **Status:** Done (v0.5.0) — verified in `server.py` and `test_phase3_phase4.py`;
  Phase 4d (Article 12 compliance report endpoint) moved to Soon

### aevum-maintainer Phase 5 (code) — Demo page static assets + deployment config
- **Why:** Public demonstration of the self-governance pipeline; demo page code
  and Fly.io configuration required before live deployment
- **Package:** aevum-maintainer (demo/)
- **Scope:** L
- **Phases:** Demo page `static/index.html` and `fly.toml` shipped; MCP tool proxy
  at `/v1/mcp/{tool_name}` exposes read-only tools to the demo page; live deployment
  is Phase 5a (Soon); interactive features are Phase 5b–5d (Backlog v0.7.0)
- **Proposed:** 2026-05 Track A audit
- **Status:** Done (v0.5.0) — code verified; deployment pending (Phase 5a)

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
