# Changelog

All notable changes to Aevum are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Aevum follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from v1.0.0 onward. Pre-1.0 versions may have breaking changes in any release.

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

[0.4.0]: https://github.com/aevum-labs/aevum/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aevum-labs/aevum/releases/tag/v0.3.0
