# Changelog

All notable changes to Aevum are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Aevum follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from v1.0.0 onward. Pre-1.0 versions may have breaking changes in any release.

## [Unreleased]

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

[0.5.0]: https://github.com/aevum-labs/aevum/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aevum-labs/aevum/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aevum-labs/aevum/releases/tag/v0.3.0
