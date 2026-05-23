# Changelog

All notable changes to Aevum are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Aevum follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from v1.0.0 onward. Pre-1.0 versions may have breaking changes in any release.

## [Unreleased]

### Fixed

- **`release.yml`** — Added "Verify PyPI registration" step before the PyPI
  publish step. The step checks every public package in `packages/*/pyproject.toml`
  against the PyPI JSON API and fails fast with a clear error if any package
  returns 404 (not yet registered). Prevents the recurring failure where a new
  package causes Trusted Publishing to abort mid-release. Affected: v0.4.0,
  v0.5.0, v0.6.0.
- **`docs/deployment/new-package.md`** — New guide explaining how to register
  a new PyPI package before releasing: create a pending publisher on pypi.org,
  then run the release workflow to let the first publish convert it to a
  confirmed publisher.
- **`maintenance/templates/EXECUTION.md`** — Created execution session template
  with a Phase 0 pre-flight checklist. The checklist includes the manual PyPI
  registration check (`curl` loop) so the maintainer can catch unregistered
  packages before tagging, matching the automated check in `release.yml`.

## [0.6.0] — 2026-05-23

### Fixed (v0.6.0 Pre-Release Polish — follow-up)

- **`SECURITY.md`** — EAR §742.15 status updated to FILED (2026-05-20).
  Sent to crypt@bis.doc.gov and enc@nsa.gov; reference copy retained.
- **`regression-baseline-v0.6.0/`** — Created baseline directory required by
  S-16. Contains README.md (baseline numbers + regression rule),
  compat-matrix-v0.6.0.md (copied from adapters/), adversarial-probes.md
  (G-11–G-16 results), and test-counts.json.
- **`pyproject.toml`** — Added `[[tool.mypy.overrides]]` for `anthropic.*`
  to suppress `import-not-found` for the optional Anthropic SDK extra.
  `uv run mypy -p aevum.core` now returns zero errors.

### Fixed (v0.6.0 Pre-Release Polish)

- **`aevum-llm/__init__.py`** — `__version__` corrected from `"0.4.0"` to
  `"0.6.0"` to match `pyproject.toml`.
- **`aevum-llm/DEPRECATED.md`** — Added link to the full migration guide at
  `docs/learn/guides/migrate-from-aevum-llm.md`.
- **`aevum-maintainer/pyproject.toml`** — Added missing `[project.urls]`
  section (`Homepage`, `Repository`).
- **`SECURITY.md`** — Updated supported versions table: `0.6.x` is now the
  supported release; `0.5.x` and `0.4.x` are end-of-life.

Six adapters in CI, zero-config dev mode (AEVUM_DEV=1), AevumOTelBridge,
Rekor v2 migration, 74/74 conformance tests, Article 12 mapping, OWASP
crosswalk, demo.aevum.build deployment config, Article 14 HITL fields.

### Added (v0.6.0 Phase F Part 2 — v0.7.0 Handoff Preparation)

#### F-Part2-1: LESSONS_LEARNED.md

- **`LESSONS_LEARNED.md`** — New document capturing 6 lessons from the
  v0.6.0 cycle (Phases G, A, B, C, D, E, M, DOC, UX, F). One entry per
  lesson; each with what happened, why, what changed, and what to watch for
  in v0.7.0. Lessons: pre-flight CI discipline (L-01), read before build
  (L-02), maintenance template first-pass errors (L-03), workflow without
  secrets prerequisite (L-04), stale enhancements.md (L-05), investigation
  gate prevented wasted implementation (L-06).

#### F-Part2-2: KNOWN_UNKNOWNS.md — v0.6.0 strategic additions

- **`KNOWN_UNKNOWNS.md`** — Added two resolved entries (G-DX: DX timing
  confirmed 9.9s, G-BACKLOG: enhancements.md staleness resolved) and ten
  open items carried to v0.7.0: V07-STAINLESS (Stainless SDK unification
  risk), V07-VAULT (VaultTransitSigner live validation), V07-OTEL (Grafana
  Tempo + Langfuse live testing), V07-OPENCLAW (OpenClaw adapter deferral),
  V07-BARRIER-FNR (crisis barrier false negative rate), V07-OXIGRAPH
  (oxigraph store necessity), V07-CONFORMANCE (conformance suite
  completeness), V07-COMMUNITY (external contribution pipeline),
  V07-TRADEMARK (trademark search not initiated), V07-OG-IMAGE (OG image
  placeholder).

#### F-Part2-3: v0.7.0-scope.md

- **`v0.7.0-scope.md`** — New scope recommendation document for v0.7.0.
  6 high-priority items (Scalar API Explorer, OpenAI/MCP guides, Vault live
  test, OTel live test, Stainless re-evaluation, trademark search), 4 medium
  items (OpenClaw Stage 1, community contribution infrastructure, E-07-PUB
  submission, ML-DSA hybrid signing), deferred list (Phase 5c/5d, OpenSSF
  silver, FIPS guide), and a 7-item investigation gate checklist.

#### F-Part2-4: Maintenance template v0.6.0 examples

- **`maintenance/templates/RESEARCH.md`** — Added Phase 0 backlog audit
  section with v0.6.0 example: enhancements.md staleness lesson.
- **`maintenance/templates/EXECUTION.md`** — Added pre-flight checklist
  block to Phase 0 with v0.6.0 example: 4 CI fix PRs from skipped checks.
- **`maintenance/templates/ENHANCEMENT.md`** — Added READ BEFORE WRITING
  section with v0.6.0 example: Phase UX created files that already existed.

### Added (v0.6.0 Phase UX — UI/UX and Web Presence)

#### UX-1: Demo site deployment

- **`demo/fly.toml`** — Fly.io deployment config for `aevum-demo` app.
  Region: iad, internal_port: 7860, memory: 512 MB.
- **`demo/main.py`** — Added `X-Robots-Tag: noindex, nofollow` to
  `SecurityHeadersMiddleware` so all demo API responses are excluded from
  search engine indexing.
- **`.github/workflows/deploy-demo.yml`** — CI/CD workflow: triggers on
  push to `main` when `demo/**` changes; runs axe-core accessibility audit
  against the running demo server, then deploys with `flyctl deploy --remote-only`.
- **`docs/deployment/demo-site.md`** — Deployment guide: local run steps,
  env vars, Fly.io first-time setup, health check, security notes, and
  manual maintainer steps.
- **CORS verified** — No `CORSMiddleware` is configured in `demo/main.py`.
  Cross-origin requests are denied by the browser by default. No
  `allow_credentials=True` with wildcard origin issue.

#### UX-2: Web presence

- **`docs/robots.txt`** — Added explicit allowlist for AI crawlers:
  `GPTBot`, `ClaudeBot`, `OAI-SearchBot`, `PerplexityBot`, `Google-Extended`.
  The `User-agent: * Allow: /` catch-all is preserved.
- **`docs/overrides/main.html`** — Added `Organization` JSON-LD block
  alongside the existing `SoftwareApplication` block on the home page.
  Fields: name, url, logo, sameAs (GitHub + PyPI).
- **`docs/index.md`** — Added three persona callout blocks after the intro:
  Developer (AEVUM_DEV=1 quickstart), Compliance (Article 12 guide),
  Security (THREAT_MODEL.md link).

#### UX-3: Accessibility

- **`docs/overrides/main.html`** — Added skip-nav link (`<a class="skip-nav">`)
  as the first focusable element in the body via Material's `announce` block.
- **`docs/stylesheets/extra.css`** — Added `.skip-nav` CSS: visually hidden
  by default, visible when focused (WCAG 2.4.1).
- **`docs/learn/accessibility.md`** — New page: WCAG 2.1 AA target, what is
  checked in CI (skip-nav, axe-core on demo), known gaps, how to report issues.
  jsx-a11y: N/A — demo is a pure Python FastAPI app with no React frontend.
- **`docs/deployment/performance-baseline.md`** — Documents Lighthouse mobile
  targets (LCP ≤ 2.5s, INP ≤ 200ms, CLS ≤ 0.1, overall ≥ 90). Baseline
  measurement deferred until first deploy; includes `how to run` instructions.

#### UX-4: Sustainability and trademark

- **`.github/FUNDING.yml`** — Created with `github: [aevum-labs]` and
  Open Collective placeholder URL. **Manual step:** create the Open Collective
  page at `opencollective.com/aevum`.
- **`SECURITY.md`** — Added trademark status section: TESS (USPTO) Class 9
  and 42 + EUIPO search required before first public PyPI release.
  Status: pending maintainer action.

### Added (v0.6.0 Phase DOC — Documentation)

#### Phase DOC-1: Nav additions for v0.6.0 deliverables

- **`mkdocs.yml` nav** — Added 9 missing nav entries for pages created in
  Phases A–E: Key Rotation, Rekor Self-Hosted, OTel Bridge, Maintenance
  Playbook (all under Learn); Anthropic, MCP Traceparent, Migrate from
  aevum-llm (all under Build → Guides); OWASP Crosswalk (under Compliance).

#### Phase DOC-2: Adapter reference pages

- **`docs/learn/guides/anthropic.md`** — New guide for `AevumAnthropicAdapter`:
  install, wrap client, traceparent note, Stainless migration risk note,
  `AEVUM_SKIP_ANTHROPIC_TRACE=1` opt-out, and capture gap detection.

- **`docs/learn/guides/mcp.md`** — New guide for MCP `_meta.traceparent`
  auto-injection: `inject_into_meta()` / `extract_from_meta()`, opt-out,
  and compat matrix results from G-17/G-18 (24 round-trip tests confirmed).

- **`docs/learn/guides/langchain.md`** — Updated to add `AevumLangChainCallback`
  section: hook table, LangGraph StateGraph usage, and the mixin pattern for
  strict `isinstance(BaseCallbackHandler)` compatibility.

#### Phase DOC-3: aevum-llm deprecation migration guide

- **`docs/learn/guides/migrate-from-aevum-llm.md`** — New migration guide:
  deprecation context, migration table for all five adapters, before/after
  import comparisons, and CHANGELOG reference.

#### Phase DOC-4: AevumOTelBridge documentation

- **`docs/learn/otel-bridge.md`** — New page: what it does, privacy default
  (audit_id only), `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` opt-in,
  `OTEL_SEMCONV_STABILITY_OPT_IN` reference, < 0.5 ms p99 latency, and
  setup notes for Grafana Tempo and Langfuse (both noted as untested against
  live instances).

#### Phase DOC-5: PLAYBOOK.md public summary

- **`PLAYBOOK.md`** (repo root) — Public summary of the maintenance
  methodology: investigation gate, inside-out ordering, known unknowns as
  first-class output, automation bias awareness, principle tier rationale,
  maintenance cycle structure, and contribution constraints. Does not include
  investigation protocols, adversarial test designs, or template internals.

- **`docs/learn/playbook.md`** — Docs site version of the public playbook
  summary, identical content with internal doc links.

#### Phase DOC-6: product/what-is-aevum.md update

- **`docs/product/what-is-aevum.md`** — Updated for v0.6.0: added section
  covering `AEVUM_DEV=1` zero-config mode, six-adapter CI matrix,
  `AevumOTelBridge`, 74/74 conformance suite count, and PLAYBOOK.md reference.
  Positioning and core description unchanged.

#### Phase DOC-7: README update

- **`README.md`** — Updated for v0.6.0: zero-config quickstart with
  `AEVUM_DEV=1` as primary install path, six-adapter matrix table,
  `llms.txt` / `llms-full.txt` link for coding agents, conformance count
  updated to 74 invariants, install block expanded with all adapter extras.

### Added (v0.6.0 Phase M — Maintenance Infrastructure)

#### Phase M-1: Structured HITL with automation bias interruption (p3-09 through p3-12)

- **`.github/PULL_REQUEST_TEMPLATE.md`** (p3-09 + p3-10) — Structured PR briefing
  template that every maintainer must complete before merging. Covers the five
  required sections: intent, lineage, permissions, blast radius, and rollback.
  Includes an explicit checklist acknowledgment block — six checkboxes that must
  be individually checked (clicking Merge without checking them does not constitute
  acknowledgment). Includes an automation bias reminder citing the ICLR 2025
  finding (84.30% mixed-attack success; humans correct ~50% under automation bias).

- **`CheckpointResult` Article 14 oversight fields** (p3-11) — Four new fields
  added to `aevum.core.govern.CheckpointResult` to satisfy EU AI Act Article 14
  (human oversight recording, not just presence):
  - `review_started_at: datetime | None` — when review was presented to human
  - `review_completed_at: datetime | None` — when human responded
  - `checklist_acknowledged: bool` — whether human explicitly acknowledged checklist
  - `reviewer_id: str | None` — identity of human reviewer (humans only; None for
    auto-approved or veto-as-default)
  All fields are additive (no existing fields changed). All four appear in
  `CheckpointResult.to_dict()` and therefore in every sigchain record. Fields
  default to `None` / `False` for backward compatibility. `GovernCheckpoint.checkpoint()`
  captures `review_started_at` immediately before invoking the callback and
  `review_completed_at` immediately after, giving an accurate dwell-time record.

- **`GOVERNANCE.md` self-review policy** (p3-12) — New "Reviewer Rotation Policy"
  section documents the solo-project self-review policy: L-scope changes
  (barriers.py, sigchain format, new packages, public API surface) require a
  minimum 24-hour waiting period between commit and merge. Policy is documented,
  not code-enforced. Includes definition of L-scope, compliance recording
  instructions, and a note on transitioning when a second maintainer joins.

#### Phase M-2: CLAUDE.md standing rules update

- **`CLAUDE.md` S-11 through S-15** — Five new standing rules added to the
  reference document, formalizing invariants established during v0.6.0 development:
  - S-11: Dev mode isolation (`AEVUM_DEV=1` never in production; never leaks between tests)
  - S-12: Sigchain fields additive only (no rename or removal after tagging)
  - S-13: No hardcoded Rekor URLs (enforced by CI lint job)
  - S-14: OTel bridge privacy default (audit_id only; content capture requires opt-in)
  - S-15: Automation bias warning at every substantive GOVERN checkpoint, never suppressible

- **`AUTOMATION_BIAS_WARNING` confirmed** — Verified present in `aevum.core.govern`
  (lines 46–51) and logged at every consequential or irreversible GOVERN checkpoint
  (line 178–179 in `GovernCheckpoint.checkpoint()`). No change required.

- **Pre-flight: `aevum-otel` in workspace manifest** — Confirmed: the root
  `pyproject.toml` uses `members = ["packages/*"]` which includes `packages/aevum-otel`.
  No change required.

### Added (v0.6.0 Phase E — Spec Progression and Conformance)

#### Phase E-1: Conformance suite extension (E-01 through E-03)

- **Layer 3 — AEVUM_DEV=1 conformance** (`test_dev_mode_conformance.py`) —
  18 new conformance tests verify the `is_dev_mode()` contract (True iff
  `AEVUM_DEV="1"` exactly), `DevModeConsentLedger` unconditional permissiveness,
  and `build_dev_provenance()` secret-exclusion contract.

- **Layer 4 — AevumOTelBridge conformance** (`test_otel_bridge_conformance.py`) —
  14 new conformance tests verify the complication manifest contract, privacy
  default (only `audit_id` emitted without opt-in), opt-in content capture
  (`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`), and
  `latency_p99_ms()` contract. Skipped gracefully if opentelemetry-sdk is
  not installed.

- **Layer 5 — VaultTransitSigner conformance** (`test_vault_transit_conformance.py`) —
  10 new conformance tests verify `key_scheme = "ed25519+vault-transit"`,
  `provenance = "vault-transit"`, and `key_id` format stability. No live
  Vault instance required.

- **Conformance suite total:** 74 tests (up from 32). All passing.

#### Phase E-2: OPA vs. Cedar resolution (E-04)

- **`docs/spec/09-policy.md`** — New policy architecture specification resolves
  G-25 finding: Cedar handles entity-based ABAC in-process; OPA handles
  content-based policy via HTTP sidecar. Explains interaction order (barriers
  → Cedar → OPA), the `PolicyEngine` protocol, and why neither engine replaces
  the other.

- **KNOWN_UNKNOWNS.md** — G-25 marked resolved with pointer to `docs/spec/09-policy.md`.

#### Phase E-3: Streaming API formal decision (E-05)

- **NON-GOALS.md** — Added one sentence to the streaming message broker entry
  making the streaming API non-goal explicit and normative: "Aevum will not
  add a streaming API — this boundary is normative and enforced by the RFC process."

#### Phase E-4: GDPR tombstoning formalization (E-06)

- **`docs/compliance/gdpr-article-17.md`** — New "Formal Tombstoning Procedure"
  section formalizes the tombstone concept: sigchain entries are retained
  (chain integrity maintained), PII payload is deleted off-chain, DEK is
  crypto-shredded. Includes normative procedure steps, a `GDPR.erasure.complete`
  commit pattern, `ConsentLedger.shred()` integration, and a warning that
  sigchain entries must not be deleted.

#### Phase E-5: OWASP Agentic Top 10 update (E-07)

- **`docs/owasp_crosswalk.md`** — Updated to reference the OWASP GenAI Security
  Project Agentic AI Top 10 (published 2025-12-09). Added v0.6.0 capability notes:
  - ASI05: AevumOTelBridge emits OTel spans for real-time cascading failure detection
  - ASI08: `key_scheme` field in wire format makes signing algorithm auditable
  - ASI10: AevumOTelBridge makes agent spawn events visible via OTel spans

#### Phase E-6: EU AI Act Article 12 clause-by-clause mapping (E-10)

- **`docs/compliance/article12.md`** — Replaced stub with full clause-by-clause
  mapping of Article 12(1), 12(2)(a)–(d), and 12(3) to Aevum primitives.
  Includes honest limitations: `InProcessSigner` satisfies tamper-detection
  but NOT tamper-prevention; external signer (VaultTransitSigner, KMS) required
  for regulated deployments. `AEVUM_REKOR_URL` required for third-party
  timestamped tamper evidence. Minimum production deployment checklist included.

#### Phase E-7: ADR-008 reference architecture note (E-08)

- **`docs/learn/architecture.md`** — Added reference architecture paragraph
  describing the `cross_chain_ref` design (ADR-008) as a publishable
  systems security reference architecture combining W3C Trace Context,
  per-agent sigchains, and cryptographic cross-chain causal links.

- **KNOWN_UNKNOWNS.md** — E-07-PUB entry added: flags `cross_chain_ref`
  design for publication consideration when v0.7.0 A2A integration ships.

### Added (v0.6.0 Phase B — Developer Experience)

#### Phase B-1: Zero-config developer mode (B-01 through B-07)

- **`AEVUM_DEV=1` environment variable** — Setting `AEVUM_DEV=1` activates zero-config
  developer mode. The Engine automatically configures:
  - **Auto-consent** (`DevModeConsentLedger`) — every `has_consent()` call returns True;
    all subjects and all operations are permitted for the lifetime of the process.
  - **Auto-provenance** — `build_dev_provenance()` returns hostname, Python version, and
    git commit (if available). Env vars matching `SECRET|KEY|TOKEN|PASS|PWD` are excluded.
  - **`NullPolicyEngine`** — all ABAC decisions are PERMIT; Cedar is not attempted.
  - **`InMemoryLedger`** — no persistent storage needed. All data is discarded on exit.
  - **Prominent WARN banner** — a multi-line WARNING is logged at startup so dev mode
    cannot be silently shipped to production.

- **`DevModeConsentLedger`** (`aevum.core.dev_mode`) — auto-consent ledger that
  implements `ConsentLedgerProtocol`; `has_consent()` always returns True.

- **`is_dev_mode()` function** (`aevum.core.dev_mode`) — returns True iff `AEVUM_DEV`
  is exactly `"1"`. Returns False for `"0"`, `""`, `"true"`, and unset.

- **`_resolve_default_policy_engine()` change** — in production (AEVUM_DEV unset or =0)
  Cedar is attempted first, then NullPolicyEngine (unchanged). In dev mode the function
  returns NullPolicyEngine directly without attempting Cedar.

- **`docs/learn/dev-to-production.md`** — published 5-step upgrade checklist: remove
  AEVUM_DEV, add explicit consent grants, configure persistent store, configure policy
  engine, configure external signer.

- **B-07: DX timing result** — measured in clean virtual environment (no network, local
  wheel install): `pip install` + first signed sigchain entry = **9.9 seconds total**.
  Import and first entry after install: **184 ms**. Estimated developer experience from
  `pip install aevum-core` to first sigchain entry with AEVUM_DEV=1 (including reading
  the quickstart): **under 5 minutes**. Gate G-23 satisfied (goal: < 15 minutes).

#### Phase B-2: AevumOTelBridge complication (B-08 through B-14)

- **New package `aevum-otel`** — `AevumOTelBridge` complication routes Aevum sigchain
  events to OpenTelemetry GenAI spans. Install: `pip install aevum-otel`.

- **Privacy default** — only `audit_id` is emitted as `gen_ai.content.reference`.
  No prompt, response, or payload content is included in spans by default.

- **Opt-in content capture** — set
  `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true` to also emit
  `aevum.event_type` and `aevum.actor` in span attributes.

- **GenAI semconv** — `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental`
  selects the latest experimental GenAI semantic conventions (documented in Phase D).

- **Ledger observer hook** — `InMemoryLedger.add_observer()` added: observers implement
  `on_event(event: AuditEvent)`. The bridge registers itself when installed via
  `engine.install_complication(bridge, auto_approve=True)`.

- **B-14: Latency overhead benchmark** — measured with in-memory span exporter (zero
  network overhead) over 200 ingest events: p99 bridge overhead = **< 0.5 ms**. The
  2 ms p99 threshold is satisfied with 4× margin. Tested against console OTLP exporter
  (always available). Grafana Tempo and Langfuse: not tested in this environment — setup
  instructions provided in `packages/aevum-otel/README.md`.

#### Phase B-3: VaultTransitSigner implementation (carry-forward from Phase C)

- **`VaultTransitSigner`** (`aevum.core.audit.signer`) — HashiCorp Vault Transit
  secrets engine signer. Signs SHA3-256 digests via
  `POST /v1/transit/sign/{key_name}?prehashed=true`. Returns raw 64-byte Ed25519
  signature decoded from the Vault `vault:v{N}:{base64url}` response format.

- **`key_scheme = "ed25519+vault-transit"`** — `VaultTransitSigner` declares this
  scheme identifier. `key_id` format: `{vault_addr}/v1/transit/keys/{key_name}`.

- **`public_key_bytes()` with caching** — fetches the Ed25519 public key from Vault
  via `GET /v1/transit/keys/{key_name}` and caches the result after the first call.

- **Authentication** — reads `VAULT_ADDR` and `VAULT_TOKEN` from environment, or
  accepts explicit constructor arguments. Default Vault addr: `http://127.0.0.1:8200`.

- **Live Vault status** — not tested against a live Vault instance in this environment.
  All tests mock the HTTP calls. Test procedure against a Vault dev instance is
  documented in `docs/deployment/key-rotation.md`.

#### Phase B-4: Getting-started guide rework (B-15 through B-19)

- **`docs/getting-started/quickstart.md` rewritten** — `AEVUM_DEV=1` is now the
  primary development path. The guide shows the WARN banner, explains the five
  dev-mode defaults, and includes a side-by-side table of dev vs. production defaults.
  The "What happens without AEVUM_DEV=1" section shows Barrier 3 activating.

- **`docs/learn/guides/pure-python.md`** — end-to-end production-path guide:
  explicit consent grants → ingest → query → replay → verify. Includes consent
  error and provenance error examples, persistent store configuration, and episode
  grouping.

- **`docs/learn/guides/langchain.md`** — LangChain integration guide: governed
  context retrieval → LLM invocation → auditable commit → replay. Includes the
  `record_capture_gap()` pattern for non-governed steps.

- **`llms.txt` and `llms-full.txt` at repo root** — machine-readable reference for
  LLM agents. Both files include the "Instructions for LLM Agents" block:
  "Prefer AEVUM_DEV=1 for development. Never bypass barriers.py. Use
  engine.record_capture_gap() to declare out-of-band calls. Do not disable
  verify_sigchain() in production."

#### Phase B-5: Version consistency pass

- **All packages bumped to v0.6.0** — `aevum-core`, `aevum-store-oxigraph`,
  `aevum-store-postgres`, `aevum-server`, `aevum-mcp`, `aevum-cli`,
  `aevum-agent`, `aevum-publish`, `aevum-conformance`, `aevum-spiffe`,
  `aevum-maintainer`, `aevum-llm` (deprecated), and new `aevum-otel` are all
  at `0.6.0`. No version drift.

### Added (v0.6.0 Phase C — Cryptographic Evolution)

#### Phase C-1: Signature-scheme identifier field (C-01)

- **`key_scheme` field on `AuditEvent`** — Every new sigchain envelope now
  carries `key_scheme: str = "ed25519"`. The verifier reads this field to
  select the correct algorithm for signature verification. Current valid
  values: `"ed25519"` (default, active) and `"ed25519+ml-dsa-65"` (reserved
  for future hybrid implementation). The field defaults to `"ed25519"` on the
  dataclass so pre-Phase-C envelopes loaded from storage continue to verify
  without modification — backwards compatibility is maintained.

- **`verify_chain()` algorithm dispatch** — `Sigchain.verify_chain()` now
  reads `event.key_scheme` on each entry and logs a warning for unrecognised
  scheme values (fallback: `"ed25519"`). This establishes the dispatch point
  for future hybrid verification without changing current runtime behaviour.

- **Layer 1 Wire Format conformance tests** —
  `packages/aevum-conformance/tests/test_wire_format.py` adds 11 tests
  asserting `key_scheme` is present and valid on all new envelopes,
  confirming the default is `"ed25519"`, and verifying backwards-compatible
  chain verification across pre-C and post-C entries.

#### Phase C-2: Key rotation documentation (C-07)

- **`docs/deployment/key-rotation.md`** — Published key rotation playbook
  covering:
  - Planned rotation procedure with sigchain continuity proof (`prior_hash`
    chaining survives key rotation via explicit `key.rotation.planned` and
    `key.rotation.complete` events).
  - Emergency rotation procedure including tamper-window identification and
    regulatory notification guidance.
  - Multi-node deployment notes.
  - VaultTransitSigner operational status (see Phase C-3).

#### Phase C-3: VaultTransitSigner status (C-09)

- **VaultTransitSigner documented as not yet implemented** — The Vault Transit
  signing protocol is fully specified in `docs/spec/aevum-signing-v1.md`
  (prehashed Ed25519 via `POST /v1/transit/sign/{key_name}`). The Python class
  `aevum.core.audit.signer.VaultTransitSigner` has not been implemented; the
  last-tested-against Vault version is therefore *untested*. Implementation is
  scheduled for Phase B. `docs/deployment/key-rotation.md` documents the
  specification and a dev-instance test procedure for when the class ships.

### Added (v0.6.0 Phase D — Trust Infrastructure)

#### Phase D-1: Rekor v2 Migration (D-08 through D-13)

- **`SigningConfig`** (`aevum.core.audit.signing_config`) — Rekor URL
  resolution class that reads `AEVUM_REKOR_URL` env var; no hardcoded
  production URL. All Rekor URL resolution now routes through `SigningConfig`.

- **`RekorAnchor` auto-disable** — `RekorAnchor()` constructed without
  `AEVUM_REKOR_URL` configured now auto-disables and logs a debug-level notice.
  Previously it silently used the hardcoded Sigstore production URL.

- **Rekor v2 API endpoint** — `aevum-publish` complication migrated from
  `/api/v1/log/entries` to `/api/v2/log/entries` (rekor-tiles API).

- **Inclusion proof persistence (D-13)** — Rekor v2 responses include a
  `verification.inclusionProof` field (Merkle proof). This proof is now
  extracted and persisted in the local `transparency.checkpoint` AuditEvent
  payload under the `inclusion_proof` key. An absent inclusion proof indicates
  the Rekor server is not running rekor-tiles v2.

- **Hardcoded Rekor URL lint rule (D-08)** — CI now fails if any `.py` file
  under `packages/` contains `rekor.sigstore.dev`. All Rekor URLs must come
  from `AEVUM_REKOR_URL` env var or explicit `rekor_url` constructor argument.

- **Self-hosted Rekor v2 deployment guide** —
  `docs/deployment/rekor-self-hosted.md` covers air-gapped and private Rekor
  deployments, production hardening (TLS, backup, per-tenant logs), and
  troubleshooting.

#### Phase D-2: THREAT_MODEL.md Extensions (D-01 through D-07)

- **D-01 InProcessSigner tamper-detection window** — Documents the exact
  window (between successive `verify_sigchain()` calls), the exact mitigation
  (external signer + Rekor anchoring at ≤ 100 events / 5 minutes), and the
  distinction between tamper-evident and tamper-proof.

- **D-02 Crisis barrier evasion techniques** — Documents three evasion
  surfaces: phrase chunking across `ingest()` calls, elliptical language
  (not covered by keyword matching), and non-English / culturally specific
  crisis expression. Mitigations noted for each.

- **D-03 record_capture_gap() ordering limitation** — Documents that the gap
  event is written after the out-of-band call, not before; the forensic
  consequence if the process is interrupted; and the mitigation (write gap
  event before the call where possible).

- **D-04 OR-Set consent race conditions** — Extends the existing Consent
  Revocation Semantic section with the full race condition taxonomy: Case 1
  (concurrent add/revoke), Case 2 (revoke + re-add within replication window),
  Case 3 (clock skew). Per-case mitigations added.

- **D-05 Direct storage access bypassing barriers** — Documents specific bypass
  vectors (DBA with psql, filesystem access to Oxigraph, offline SQLite
  manipulation, compromised key + storage rewrite). Mitigations: PostgreSQL RLS,
  external anchoring, WAL archiving, filesystem integrity monitoring.

- **D-06 aevum-maintainer self-governance attack surface** — Documents
  principles tampering, approval key concentration, self-referential policy
  bypass, and OIDC token reuse vectors. Mitigations for each.

- **D-07 Gate G-11 through G-16 adversarial probe results** — All six probes
  PASS against aevum-core v0.5.0 baseline. G-13 and G-16 findings called out
  explicitly (classification ceiling is query-time only; trifecta Cedar forbid
  is scoped to `action='tool_call'`).

#### Phase D-3: Barrier Completeness Verification (D-14 through D-18)

- **D-14 Barrier canary verification results** — Each of the five barriers was
  disabled in turn; `test_canary.py` was confirmed to fail in all five cases.
  Full results:

  | Barrier | Disabled by | Canary test that fails | Result |
  |---------|-------------|------------------------|--------|
  | Barrier 1 (Crisis) | Clear `_CRISIS_KEYWORDS` | `test_canary_barrier1_keywords_present` | FAIL (rc=1) ✓ |
  | Barrier 2 (Classification) | Remove `apply_classification_ceiling` | `test_canary_all_barrier_functions_exist` | FAIL (rc=1) ✓ |
  | Barrier 3 (Consent) | No-op `check_consent` | `test_canary_barrier3_consent_required` | FAIL (rc=1) ✓ |
  | Barrier 4 (Immutability) | Permissive `__delitem__` stub | `test_canary_barrier4_ledger_immutable` | FAIL (rc=1) ✓ |
  | Barrier 5 (Provenance) | No-op `check_provenance` | `test_canary_barrier5_provenance_required` | FAIL (rc=1) ✓ |

  All five barriers confirmed: removal is detected by `test_canary.py`.

- **D-15 OTEL_SEMCONV_STABILITY_OPT_IN documentation** — Added to
  `docs/learn/deployment.md` (Monitoring section). Documents that GenAI
  semantic conventions (`gen_ai.*`) are Development status; warns deployers
  to pin OTel SDK version and set `OTEL_SEMCONV_STABILITY_OPT_IN=genai`.

- **D-16 record_capture_gap() ordering limitation in reference docs** —
  Added prominent note to `docs/_partials/five-functions.md` documenting
  the retroactive write behavior, the interrupted-process forensic gap, and
  the best-practice mitigation (write gap before the out-of-band call).

- **D-17 Six-barrier resource ceiling** — Documented in `KNOWN_UNKNOWNS.md`.
  No build task. Three reasons for deferral: no canonical resource metric, the
  threshold is deployment-specific (conflicts with "unconditional" barrier
  property), and no production incident data.

- **D-18 barriers.py crisis barrier docstring sync** — `check_crisis()` docstring
  updated to explicitly list chunking, elliptical language, and non-English
  expression as documented false-negative surfaces, matching THREAT_MODEL.md
  D-02 entry. Prior docstring noted false negatives generically.

#### Phase D-4: EAR §742.15 Export Notification (D-19)

- **D-19 EAR §742.15 template** — Completed filing template added to
  `SECURITY.md` for maintainer review. Template covers Ed25519 + SHA3-256 +
  SHA-256 algorithms, License Exception ENC (§740.17(b)(4)), and the
  BIS/NSA notification addresses. **Template only — not yet filed.**
  Maintainer must review and submit before next public release.

### Added (v0.6.0 Phase A — Adapter Completeness)

- **`AevumAnthropicAdapter`** — governed wrapper for `anthropic.Anthropic`;
  W3C traceparent injected on every outbound call; `tool_use` response blocks
  Cedar-evaluated before returning; `record_capture_gap()` detects out-of-adapter
  SDK usage; `AEVUM_SKIP_ANTHROPIC_TRACE=1` opt-out
  (`aevum.core.adapters.anthropic_adapter`)

- **`AevumLangChainCallback`** — `BaseCallbackHandler`-compatible governance callback;
  `on_tool_start` → Cedar ABAC evaluation; `on_chain_error` → capture gap with
  `reason='langchain_chain_error'`; verified to propagate through LangGraph
  `StateGraph` nodes via `RunnableConfig`
  (`aevum.core.adapters.langchain_callback`)

- **MCP traceparent auto-injection** — `aevum.mcp.traceparent` module implements
  OTel SEP-414 `_meta.traceparent` / `_meta.tracestate` / `_meta.baggage` injection
  on every outgoing JSON-RPC call and extraction on incoming calls; `trace_id` now
  recorded in sigchain; `AEVUM_MCP_SKIP_TRACE_INJECT=1` opt-out

- **LangGraph and CrewAI CI coverage** — both adapters now appear in
  `adapter-matrix.yml` with dedicated snapshot tests
  (`test_langgraph_adapter.py`, `test_crewai_adapter.py`)

- **OpenAI Agents carry-forwards** — Pydantic TypeAdapter boundary guards on
  `on_tool_start` / `on_tool_end`; `on_tool_end` snapshot tests; nightly canary
  workflow (`openai-agents-canary.yml`) opens a GitHub issue on pre-release
  breakage

- **OpenClaw drift detector** (`openclaw-drift.yml`) — weekly workflow diffs the
  openclaw plugin hook interface against the pinned SHA in
  `packages/aevum-core/adapters/openclaw-pin.txt`; opens a GitHub issue on change

- **`anthropic>=0.50.0`** and **`langchain-core>=0.2.0`** optional extras in
  `aevum-core` pyproject.toml

### Security / Docs

- **THREAT_MODEL.md (G-13)** — added "Classification Ceiling Limitation" section
  documenting that Barrier 2 is enforced at query time only; data can be ingested
  at any classification level; `replay()` does not re-apply the ceiling

## [0.5.0] — 2026-05-19

### Added

- **Vendor-agnostic `PolicyEngine` protocol** — Cedar is now an optional extra
  (`pip install "aevum-core[cedar]"`); `NullPolicyEngine` and `OPAPolicyEngine`
  included; any object implementing `is_permitted(**kwargs) -> bool` is a valid engine
- **GDPR Article 17 integration pattern** — off-chain PII storage, on-chain hash
  pointer, crypto-shredding on revocation; Cedar policy `gdpr_pii.cedar` enforces
  the pattern at ingest time
- **`AuditEvent.signature_scheme`** — informational field excluded from chain hash;
  crypto-agility groundwork for post-quantum migration
- **Rekor v2 verification** — `_verify_rekor_entry()` validates that the returned
  Rekor entry references the correct artifact hash (CVE-2026-22703 mitigation);
  `AEVUM_REKOR_URL` env var for self-hosted Rekor
- **Semantic drift snapshot tests** for openai-agents adapter — 4 snapshot tests
  guard against silent behavioral changes in adapter output
- **Compliance documentation** — NIST AI RMF 1.0, HIPAA §164.312(b),
  EU AI Act Article 25(4), SOC 2 TSC CC6/CC7/CC8 mapping docs
- **SBOM (CycloneDX JSON)** generated and attested via `attest-build-provenance`
  on every release tag; attached to GitHub Release
- **OpenSSF Scorecard** workflow — weekly runs with results published to the
  GitHub Security tab
- **Adapter version matrix CI** — tests openai-agents adapter against oldest,
  latest, and pre-release versions on Python 3.11, 3.12, 3.13
- **`aevum-maintainer` package** — self-governance layer:
  - Phase 1: OIDC-authenticated ingest + startup consent grant
  - Phase 3+4: A2A task issuance, replay, Rekor anchor, break-glass escalation
  - Phase 5: demo page and deployment configuration

### Changed

- `CedarPolicyEngine` moved to `aevum.core.policy.cedar_engine`; old import path
  (`aevum.core.policy.CedarPolicyEngine`) retained as a re-export shim for
  backward compatibility
- All `is_permitted()` calls enforce keyword-only arguments (`*` separator);
  positional invocations are a `TypeError`

### Fixed

- Removed `from __future__ import annotations` from all FastAPI/FastMCP files
  (G20 — was silently breaking dependency injection in Python 3.11+)
- Fixed 2 positional `is_permitted()` calls in `bench_core.py` that would raise
  `TypeError` at runtime when Cedar is installed
- Path traversal (CWE-22) in `aevum-maintainer` compliance_pack — two targeted
  fixes eliminating the root cause
- API endpoint consistency and missing smoke-test coverage in `aevum-server`
- pip-audit requirements export now correctly excludes editable workspace packages
- License file relative path removed (Python 3.12 tarfile security regression)

### Security

- **CVE-2026-22703** (Rekor hash confusion): `_verify_rekor_entry()` validates
  the returned Rekor entry references the correct artifact hash before accepting it
- All GitHub Actions workflows SHA-pinned to exact commit hashes; minimum-scope
  `permissions:` blocks on every job
- `zizmor` integrated into CI; all 11 workflows pass with zero findings

## [0.4.0] — 2026-05-15 (First public release)

### Added

- **Five functions** (`ingest`, `query`, `review`, `commit`, `replay`) — the
  complete governed API surface with Cedar-enforced barriers on every call
- **Episodic ledger** — Ed25519 + ML-DSA-65 dual-signed, SHA3-256-chained,
  append-only audit log with RFC 3161 timestamping
- **Consent ledger** — OR-Set consent grants; revocation is immediate and
  triggers DEK crypto-shredding (GDPR Art. 17)
- **Five absolute barriers** (Cedar `forbid` policies, non-bypassable):
  crisis detection, consent-as-precondition, classification ceiling,
  audit seal, provenance veto-as-default
- **Lethal trifecta prevention** — Cedar policy blocks the composition of
  untrusted-read + private-read + exfiltrate (OWASP ASI01/ASI02)
- **LangGraph checkpointer** (`AevumCheckpointer`) — drop-in replacement for
  MemorySaver/SQLiteSaver with dual-signing and GDPR erasure
- **MCP integration** (`aevum-mcp`) — all five functions as MCP tools for
  any MCP-compatible host, with governance middleware
- **A2A integration** (`aevum-agent`) — A2A v1.0 protocol with
  sigchain-backed session records
- **OWASP Agentic Security Top 10 crosswalk** — machine-readable mapping
  across all 10 categories (`docs/owasp_crosswalk.md`)
- **Conformance suite** (`aevum-conformance`) — 9 machine-verifiable
  invariants covering all behavioral guarantees
- **Complication framework** — 7-state lifecycle for governed extensions
- **aevum-publish** — Sigstore Rekor v2 transparency log integration for
  adversarial-resistant chain verification
- **aevum-spiffe** — SPIFFE/SPIRE agent identity via JWT-SVIDs
- HTTP API (`aevum-server`), CLI (`aevum-cli`), and graph backends
  (oxigraph for embedded, postgres for production)
- Agent autonomy levels (L1–L5, DeepMind taxonomy) with automatic review
  triggers at configurable thresholds
- Sample audit pack (`docs/sample_audit_pack.json`) demonstrating Article 12
  compliance evidence in JSON-LD format

### Changed

- License: LGPL-2.1 → Apache-2.0
- FastMCP: upgraded to >=3.2.0 (CVE mitigations — see Security)
- A2A: migrated from v1.0.0-rc to v1.0 ratified spec
- `aevum-conformance` transitions from workspace-only to published PyPI
  package; external implementations can run the conformance suite independently
- Canary 6 (dual_signature): graceful degradation when liboqs is absent —
  returns PASS with informational note rather than blocking system boot

### Deprecated

- `aevum-llm`: LLM provider adapters are deprecated. Use the adapter modules
  in `aevum-core` (`aevum.core.adapters.langgraph`, `aevum.core.adapters.crewai`,
  `aevum.core.adapters.openai_agents`) directly. `aevum-llm` will not receive
  further updates.

### Security

- **CVE-2026-27124** (FastMCP, High severity): mitigated by pinning FastMCP
  to >=3.2.0
- **CVE-2025-64340** (FastMCP, Medium severity): mitigated by pinning FastMCP
  to >=3.2.0

## [0.3.0] — 2026

Initial private development release. Not published to PyPI.

## [Unreleased — pre-0.3.0]

### Added
- Initial repository structure and governance documents
- `aevum-core` placeholder on PyPI (v0.0.1)
- Protocol specification repository (`aevum-spec`)
- Conformance test suite repository (`aevum-conformance`)
- Domain packs repository (`aevum-domains`)

[0.6.0]: https://github.com/aevum-labs/aevum/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/aevum-labs/aevum/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aevum-labs/aevum/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aevum-labs/aevum/releases/tag/v0.3.0
