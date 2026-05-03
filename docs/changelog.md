---
description: "Release history for Aevum v0.3.0: five governed functions, five absolute barriers, Ed25519 sigchain, Cedar policy, MCP integration, and 280 tests."
---

# Changelog

## v0.3.0 — May 2026

First public release.

**Packages:** aevum-core, aevum-server, aevum-sdk, aevum-store-oxigraph,
aevum-store-postgres, aevum-mcp, aevum-oidc, aevum-llm, aevum-cli,
aevum-store-jena (stub)

**What's in this release:**

- Five governed functions: `ingest`, `query`, `review`, `commit`, `replay`
- Five absolute barriers: crisis detection, classification ceiling, consent, audit immutability, provenance
- Ed25519 sigchain + SHA3-256 hash chaining
- Cedar in-process policy + OPA HTTP sidecar
- Complication framework with 7-state lifecycle
- Agent autonomy levels L1–L5 (DeepMind taxonomy)
- A2A task format (`create_task`, `get_task` MCP tools)
- Full test suite: 280 tests, mypy strict, ruff clean
- MCP integration for any MCP-compatible host

---

## v0.1.0 — 2026

Initial repository structure. `aevum-core` placeholder on PyPI.

- Initial repository structure and governance documents
- `aevum-core` placeholder on PyPI (v0.0.1)
- Protocol specification repository (`aevum-spec`)
- Conformance test suite repository (`aevum-conformance`)
- Domain packs repository (`aevum-domains`)
