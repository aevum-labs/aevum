---
description: "Release history for Aevum v0.3.1: five governed functions, five absolute barriers, Ed25519 sigchain, Cedar policy, MCP integration, and 290+ tests."
---

# Changelog

## v0.3.1 — May 2026

**Context Witness — TOCTOU protection (Phase 12a)**

- `query()` now captures a Witness snapshot (sigchain sequence
  watermark + SHA-256 result digest) returned in `data["witness"]`
- `commit()` accepts optional `witness=` parameter; validates
  staleness before any ledger write
- Stale commits return `status="error"`, `error_code="stale_context"`
  and log a `context.stale` event to the sigchain
- `InMemoryLedger` and `PostgresLedger` gain
  `max_sequence_for_subjects()` for watermark lookup
- 12 new tests in `test_witness.py`; total 137 tests (aevum-core)

**Complication Outcome Convention (Phase 12b)**

- Spec Section 11.6 defines the outcome event obligation for
  complications that execute irreversible actions
- Event types `action.outcome.ok`, `action.outcome.failed`,
  `action.outcome.partial` are now reserved and documented
- `context.stale` and `action.outcome.*` added to reserved
  event type prefix list in spec Section 8

---

## v0.3.0 — May 2026

First public release.

**Packages:** aevum-core, aevum-server, aevum-store-oxigraph,
aevum-store-postgres, aevum-mcp, aevum-cli

**What's in this release:**

- Five governed functions: `ingest`, `query`, `review`, `commit`, `replay`
- Five absolute barriers: crisis detection, classification ceiling, consent, audit immutability, provenance
- Ed25519 sigchain + SHA3-256 hash chaining
- Cedar in-process policy + OPA HTTP sidecar
- Full test suite: 287 tests, mypy strict, ruff clean
- MCP integration for any MCP-compatible host

---

## v0.1.0 — April 2026

Initial repository structure. `aevum-core` placeholder on PyPI.

- Initial repository structure and governance documents
- `aevum-core` placeholder on PyPI (v0.0.1)
- Protocol specification repository (`aevum-spec`)
- Conformance test suite repository (`aevum-conformance`)
- Domain packs repository (`aevum-domains`)
