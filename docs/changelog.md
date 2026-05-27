---
description: "Release history for Aevum — current version v0.7.1."
---

# Changelog

## v0.7.1 — May 2026

**Current stable release.**

Packages published to PyPI:
`aevum-agent`, `aevum-cli`, `aevum-conformance`, `aevum-core`,
`aevum-mcp`, `aevum-otel`, `aevum-publish`, `aevum-server`,
`aevum-spiffe`, `aevum-store-oxigraph`, `aevum-store-postgres`

**Changes in v0.7.1:**

- Demo consolidation: single Fly.io app now serves both the React SPA and the
  API from `demo.aevum.build`. The separate `deploy-frontend.yml` workflow was
  removed.
- `demo/src/api.ts`: `API_BASE` falls back to `''` (same-origin) when
  `VITE_API_URL` is unset, ensuring health checks and API calls work without
  configuration.
- VaultTransitSigner: fixed `prehashed=True` bug (Vault 2.x Ed25519 requires
  Pure Ed25519, not pre-hashed mode).
- VaultTransitSigner: added `verify()` method (was absent).
- VaultTransitSigner: fixed base64 encoding mismatch (standard vs URL-safe).
- Added `aevum vault-check` CLI command — verifies Vault Transit connectivity
  with a sign/verify round-trip.
- Added integration tests for VaultTransitSigner (8 tests, live Vault).
- Fixed `--clobber` flag in `release.yml` (unsupported in current `gh` CLI).

---

## v0.7.0 — May 2026

**First major release.**

Packages published to PyPI:
`aevum-agent`, `aevum-cli`, `aevum-conformance`, `aevum-core`,
`aevum-mcp`, `aevum-otel`, `aevum-publish`, `aevum-server`,
`aevum-spiffe`, `aevum-store-oxigraph`, `aevum-store-postgres`

**What's in v0.7.0:**

- COSE_Sign1 receipts (`aevum-publish`) with SCITT profile headers and
  `AmbientContextReceipt` cross-chain reference architecture
- Three-tier SQLite WAL receipt store with hot/warm/cold tier management
- QAR/FOQA analytics layer: `ExceedanceDetector`, `GatekeeperFilter`, `FOQABridge`
- Five framework adapters (OpenAI Agents SDK, LangGraph, CrewAI, Google ADK,
  Microsoft Agent Framework) in `aevum-agent`
- MCP Docker Gateway shim and A2A ASGI audit middleware
- OPA full-barrier fallback with Rego parity policies
- ML-DSA-65 (FIPS 204) dual signing via `aevum-core[oqs]`
- zizmor GitHub Actions security scanner in CI
- SPDX `Apache-2.0` license headers across all 9 packages
- Demo: Vite/React stepper frontend with Scalar API explorer
- Full test suite: 290+ tests, mypy strict, ruff clean

---

## v0.6.0 — May 2026

- OTel semconv migration (`gen_ai.system` → `gen_ai.provider.name`)
- `AevumOTelBridge` privacy-preserving defaults (S-14)
- ML-DSA-65 dual-signing architecture and `liboqs` integration (Session 13)
- SPIFFE integration (`aevum-spiffe`) and SVID-based identity binding
- FOQA de-identification spec and SCITT profile

---

## v0.5.0 — May 2026

- `aevum-server` HTTP API wrapper (FastAPI)
- Session-level review gates with autonomy enforcement
- OR-Set CRDT consent ledger for distributed revocation
- Hybrid Logical Clock (HLC) for monotonic distributed timestamps
- MCP integration (`aevum-mcp`) for Claude Desktop, Cursor, VS Code Copilot

---

## v0.4.0 — May 2026 (First public release)

- Five governed functions: `ingest`, `query`, `review`, `commit`, `replay`
- Five unconditional barriers: crisis detection, classification ceiling, consent,
  audit immutability, provenance
- Ed25519 sigchain + SHA3-256 hash chaining
- Cedar in-process policy + OPA HTTP sidecar
- Full test suite: 287 tests, mypy strict, ruff clean

---

## Earlier versions

v0.3.x and earlier were pre-release development iterations.
See the [GitHub releases page](https://github.com/aevum-labs/aevum/releases)
for the complete history.
