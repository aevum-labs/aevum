# Aevum v0.8.0 Kickoff

Generated: 2026-06-05
Predecessor: v0.7.2

## State entering v0.8.0

- 13 packages published at v0.7.2
- Conformance: 11/11
- Test count: 1382 passed, 102 skipped, 0 failures
- PyPI: all public packages published, Trusted Publishing active
- Private packages excluded from PyPI: aevum-maintainer, aevum-llm

## v0.8.0 Candidate Items

### High priority

- VaultTransitSigner live test (V07-VAULT still open — implementation complete, live verification deferred)
- MCP SEP-1763 — track experimental-ext-interceptors for Python "Planned" → "In Progress" status change
- ScittTsBackend implementation (when ScrAPI draft reaches RFC)
- OpenClaw Stage 1 integration (cut from v0.7.0)
- ML-DSA hybrid signing (cut from v0.7.0)

### Medium priority

- AEVUM_V080_KICKOFF.md automated generation in release.yml
- rotate_operational() scheduled job (maintainer must invoke manually — recommended daily)
- aevum-demo.fly.dev cleanup/decommission (now superseded by aevum-maintainer at demo.aevum.build)

### Known open items

- V07-VAULT: VaultTransitSigner live verification deferred
- Trademark status: confirm with IP counsel
- cedarpy fork: aevum-labs/cedar-py — confirm created

## Architecture notes for v0.8.0 planning

- COSE_Sign1 bare array encoding (not CBORTag(18)) — do not change; verified throughout codebase
- Signing uses Signer protocol with SHA3-256 prehash — never use raw PyNaCl directly
- AevumReceipt lives in aevum.core.receipt, not aevum.publish
- _MaintenanceStore persists to /data/aevum_maintainer.db on Fly.io — InMemoryLedger replays from it on startup
- demo.aevum.build DNS: A → 66.241.124.38 (aevum-maintainer) — do not change

## Regulatory tracking

- EU AI Act Annex III deadline: December 2, 2027 (Digital Omnibus provisional agreement May 7, 2026)
- Colorado SB 26-189: effective January 1, 2027
- Next review recommended before any compliance documentation updates
