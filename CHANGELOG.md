# Changelog

All notable changes to Aevum are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Aevum follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from v1.0.0 onward. Pre-1.0 versions may have breaking changes in any release.

## [Unreleased]

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

[0.5.0]: https://github.com/aevum-labs/aevum/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aevum-labs/aevum/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aevum-labs/aevum/releases/tag/v0.3.0
