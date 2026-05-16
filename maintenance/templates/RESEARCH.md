AEVUM MONTHLY RESEARCH
=======================
Role:      Claude (claude.ai) — research, analysis, classification
Execution: hand Research Report to Claude Code via EXECUTION.md
Generated: {{GENERATED_TIMESTAMP}}

Principle: Claude researches and classifies. Claude Code executes and commits.
           you review gate reports and make release decisions.
           Think smarter, not harder.

=======================
STARTING STATE
=======================
Month:    {{MONTH_YEAR}}
Version:  {{CURRENT_VERSION}}
Deferred: {{DEFERRED}}
Last run: {{LAST_RUN_DATE}}

=======================
GITHUB ACTIONS SCAN RESULTS
=======================
Auto-embedded by maint_kickoff.py from maintenance/scan_results.md.
If this section is empty, trigger the monthly-maintenance workflow first:
  GitHub → Actions → monthly-maintenance → Run workflow
Then re-run: python scripts/maint_kickoff.py

{{SCAN_RESULTS}}

=======================
AEVUM IN BRIEF
=======================
Open-source AI context kernel. Apache-2.0. Solo-maintained.
Five governed functions: ingest, query, review, commit, replay.
Five absolute barriers: Crisis, Classification Ceiling, Consent,
  Audit Immutability, Provenance.
Ed25519 + SHA3-256 sigchain, RFC 3161 timestamping, Cedar policy engine (cedarpy).
MCP integration (aevum-mcp), A2A v1.0.0-rc task format (aevum-agent, task format only).
mkdocs-material docs at aevum.build. EU AI Act Article 12 compliant.
Docs ship with every release — code without matching docs does not ship.

Key deps: cedarpy>=4.8.1, pydantic>=2.0<3.0, cryptography>=42.0, PyNaCl>=1.5.0,
  liboqs-python>=0.10.0, rfc3161-client>=1.0.0, fastmcp>=3.2.0, rdflib>=7.0,
  pyshacl>=0.25.0, psycopg3, fastapi, typer, pyoxigraph (via oxrdflib)

=======================
PHASE 1 — SECURITY
=======================
The step summary is the primary signal. This phase adds exploitability context
and catches anything pip-audit has not yet indexed.

For each CVE in the step summary, assess:
  — Is Aevum's usage actually exploitable? (A web-server CVE in a lib Aevum uses
    only for crypto is not exploitable through Aevum — say so clearly.)
  — Minimum safe fix version?

Search for CVEs in the past 30 days not yet in OSV:
  "CVE cryptography python {{CURRENT_YEAR}} advisory"
  "CVE cedarpy cedar policy security"
  "CVE fastmcp {{CURRENT_YEAR}}"
  "CVE liboqs PyNaCl {{CURRENT_YEAR}}"

Classify:
  CRITICAL — CVSS >= 7.0 in crypto chain (cryptography, PyNaCl, liboqs)
             OR CVSS >= 7.0 direct dep with confirmed exploit path in Aevum
  HIGH     — CVSS 4.0–6.9 direct dep
  MEDIUM   — CVSS < 4.0, or high-CVSS transitive with no exploit path
  LOW      — informational

=======================
PHASE 2 — PROTOCOL DRIFT AND OPPORTUNITIES
=======================
Protocol drift silently leaves Aevum non-conformant. New protocol capabilities
are also opportunities to strengthen Aevum's conformance story.
For each: note what changed AND what Aevum should do about it.

MCP (Model Context Protocol)
  Fetch: https://github.com/modelcontextprotocol/specification/releases
  Assess: current spec version? New message types, tool schemas, resource types?
          Breaking changes to types Aevum uses?
  Respond: Required new capability → HIGH maintenance fix this session.
           Optional but valuable → enhancement proposal with scope estimate.

A2A (Agent2Agent)
  Fetch: https://github.com/google-a2a/A2A/releases
  Assess: still v1.0.0-rc or ratified to GA? Task format changes?
          (Aevum implements task format only — not a full HTTP server.)
  Respond: Ratification or breaking format change → HIGH maintenance.
           New optional fields that strengthen conformance → enhancement proposal.

Cedar / cedarpy
  Fetch: https://pypi.org/pypi/cedarpy/json
  Assess: latest vs pin (>=4.8.1). Security advisory? API breakage?
          We use plain dicts — confirm that still works with latest.
  Respond: Security → CRITICAL or HIGH. New language features that improve
           Aevum's policy expressiveness → enhancement proposal.

FastMCP
  Fetch: https://pypi.org/pypi/fastmcp/json
  Assess: latest vs pin. New CVEs beyond CVE-2026-27124 / CVE-2025-64340?
          Breaking server API changes?

Classify each: CRITICAL (breaking) / HIGH (required) / MEDIUM (optional) / LOW

=======================
PHASE 3 — COMPLIANCE AND GAPS
=======================
Aevum makes specific compliance claims. Verify accuracy. Flag any gap that
has become a liability or an opportunity to strengthen the claim.

EU AI Act — Article 12
  Search: "EU AI Act Article 12 implementing act {{CURRENT_YEAR}}"
  Search: "EU AI Act technical standards audit trail {{CURRENT_YEAR}}"
  Assess: new implementing acts? Sigchain + RFC 3161 + SBOM still satisfy guidance?
  Respond: New hard requirement → HIGH (code or docs). Opportunity to strengthen
           Article 12 coverage → enhancement proposal.

OWASP Agentic AI Top 10
  Search: "OWASP Agentic AI Top 10 {{CURRENT_YEAR}} update"
  Assess: new version? Map Aevum's five barriers to the current list.
          Any new risk none of the barriers address?
  Respond: Unaddressed risk while we claim OWASP alignment → HIGH at minimum.
           Opportunity to extend barrier coverage → enhancement proposal.

OpenSSF Scorecard
  Search: "OpenSSF Scorecard new checks {{CURRENT_YEAR}}"
  Assess: new checks that would affect Aevum's score? (Full run is quarterly.)

Classify: CRITICAL (claim now wrong) / HIGH (code or docs fix) /
          MEDIUM (docs update) / LOW (no change)

=======================
PHASE 4 — COMPETITIVE INTELLIGENCE
=======================
Goal: determine what Aevum should DO, not just observe what exists.
"What shipped?" is the wrong question. "Does Aevum need to respond?" is right.

Search:
  "AI agent governance audit trail open source {{CURRENT_YEAR}}"
  "MCP governance security policy open source {{CURRENT_YEAR}}"
  "EU AI Act compliance tooling open source Python {{CURRENT_YEAR}}"
  "LangChain CrewAI OpenAI Agents governance audit {{CURRENT_YEAR}}"

For each notable development:
  OBSERVE  — what shipped or changed in the ecosystem?
  ASSESS   — does Aevum address this? Better, worse, or differently than alternatives?
             Is there a capability gap that matters to real adopters today?
  RESPOND  — what should Aevum do?
             → Nothing needed (differentiation intact)
             → Positioning or docs update (no code change) — flag as MEDIUM
             → Enhancement proposal (new capability — provide scope and priority)

Classify:
  HIGH   — Aevum is missing something that materially matters to adopters
  MEDIUM — positioning or docs update warranted; no code change yet
  LOW    — noting for awareness only

=======================
PHASE 5 — DEPENDENCY UPDATES
=======================
The step summary lists available updates. Classify them for Claude Code.

  SAFE TO APPLY — patch bump, confirmed non-breaking minor, no changelog warning
  HOLD          — major bump, unconfirmed minor, or breaking changes noted

Reference pins:
  pydantic>=2.0,<3.0   cryptography>=42.0   cedarpy>=4.8.1
  PyNaCl>=1.5.0        liboqs-python>=0.10.0  rfc3161-client>=1.0.0
  pyshacl>=0.25.0      rdflib>=7.0.0          fastmcp>=3.2.0

=======================
PHASE 6 — DOCUMENTATION HEALTH
=======================
The science experiment standard: following the docs should reproduce the result.
Surface gaps so Claude Code can fix them this session.

Getting-started — does the published example work with v{{CURRENT_VERSION}}?
  Fetch the getting-started page from aevum.build.

API drift — any public signature changes since the last release?
  Check recent commits via GitHub MCP or recent commit search.

CHANGELOG — complete entry for v{{CURRENT_VERSION}}? [Unreleased] section current?
  Fetch: https://raw.githubusercontent.com/aevum-labs/aevum/main/CHANGELOG.md

Version consistency — pyproject.toml = mkdocs.yml = README badge = PyPI page?
  Fetch: https://pypi.org/pypi/aevum-core/json → info.version

Classify: CRITICAL (getting-started broken) / HIGH (API undocumented, wrong version) /
          MEDIUM (minor inaccuracy) / LOW (cosmetic)

=======================
RESEARCH REPORT
=======================
(Claude fills this completely. paste it into EXECUTION.md.)

=================================================================
AEVUM RESEARCH REPORT — {{MONTH_YEAR}}
=================================================================

SECURITY
  CRITICAL: [dep / CVE-ID / CVSS / fix version / exploit path — or: none]
  HIGH:     [list — or: none]
  MEDIUM:   [list — or: none]

PROTOCOLS
  MCP:     [version / change / action — or: no change]
  A2A:     [rc or GA / format change / action — or: no change]
  Cedar:   [latest / pin >=4.8.1 / advisory / action — or: no change]
  FastMCP: [latest / new CVEs / action — or: no change]

COMPLIANCE
  EU AI Act:  [new guidance / claims accurate / action — or: no change]
  OWASP:      [new version / barrier gaps / action — or: no change]
  OpenSSF:    [new checks / action — or: no change]

COMPETITIVE LANDSCAPE
  [notable shift + Aevum's position + response — or: differentiation intact]

DEPENDENCY UPDATES
  SAFE TO APPLY: [dep → version — or: none]
  HOLD:          [dep → version, reason — or: none]

DOCUMENTATION
  Getting-started: [PASS / FAIL — description]
  API drift:       [description — or: none]
  CHANGELOG:       [complete / gaps: description]
  Version nums:    [consistent / issues: list]

─────────────────────────────────────────────────────────────────
MAINTENANCE ACTION LIST  (Claude Code applies this session)
─────────────────────────────────────────────────────────────────
  CRITICAL: [numbered — or: none]
  HIGH:     [numbered — or: none]
  DOC FIXES (required before any release): [numbered — or: none]
  MEDIUM (log only — do not act this session): [numbered — or: none]

─────────────────────────────────────────────────────────────────
ENHANCEMENT PROPOSALS  (your reviews; implemented via ENHANCEMENT.md)
─────────────────────────────────────────────────────────────────
  S — Small:  single session, one or two files, follows existing pattern
  M — Medium: single session with checkpoints (or two sessions), new test module
  L — Large:  multi-session, phased — include a suggested phase breakdown

  Format per proposal:
    What:      [capability]
    Why:       [driver — protocol / compliance / competitive]
    Package:   [which package(s)]
    Scope:     [S / M / L]
    Phases:    [for M/L — one line per phase, each independently testable]
    Priority:  [NOW / SOON / BACKLOG]

  ── Example S ──────────────────────────────────────────────────
  What:     Add MCP audio resource type to aevum-mcp
  Why:      MCP spec v2.1; adopters using voice features will encounter this
  Package:  aevum-mcp
  Scope:    S — one new class, follows TextResource pattern
  Priority: SOON

  ── Example M ──────────────────────────────────────────────────
  What:     Implement A2A task streaming in aevum-agent and aevum-server
  Why:      A2A ratified to GA; streaming task updates now required for conformance
  Package:  aevum-agent, aevum-server
  Scope:    M
  Phases:   1. StreamingTask class in aevum-agent, unit tests passing
            2. SSE endpoint in aevum-server, end-to-end test, docs updated
  Priority: NOW — A2A conformance claim at risk

  ── Example L ──────────────────────────────────────────────────
  What:     Add FHIR R4 domain module (aevum-domains-fhir)
  Why:      Regulated healthcare vertical; first beachhead domain module
  Package:  new package aevum-domains-fhir
  Scope:    L
  Phases:   1. Package scaffold, FHIR R4 resource ingestion, unit tests
            2. SHACL validation integration, complication definitions
            3. End-to-end test, full docs section, conformance additions
  Priority: SOON

  [or: none this month]

─────────────────────────────────────────────────────────────────
  Estimated Claude Code session time: [X min]
  the maintainer decision needed before Claude Code runs: [yes — describe / no]
=================================================================
END RESEARCH REPORT
=================================================================
