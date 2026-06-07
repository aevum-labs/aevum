---
description: "Aevum v0.7.3 test coverage baseline: 1389 passing, 102 skipped — categorized by skip reason."
---

# Test Coverage

As of v0.7.3: **1389 passing, 102 skipped, 10 deselected** (integration mark).

---

## Skipped test categories

### Bucket A — Optional dependency not installed (90 tests)

These tests skip automatically when optional packages are absent. They are correct
behavior — each test runs when the optional dependency is installed.

| Optional package | Tests skipped | Test file(s) |
|---|---|---|
| `cedarpy` | 35 | `test_cedar_policy.py`, `test_phase2_govern.py`, `test_policy_protocol.py`, `test_phase2_cedar_engine.py`, `test_phase2_trifecta.py` |
| `langgraph-checkpoint` | 45 | `test_phase7_langgraph.py` |
| `opentelemetry-sdk` | 0 (installed) | `test_otel_bridge_conformance.py` |

Install all optional extras to run the full suite:

```bash
pip install 'aevum-core[cedar,adk,maf,langchain,langgraph,crewai,openai-agents,anthropic]'
uv run pytest packages/
```

### Bucket B — Integration tests requiring live external services (12 tests)

These tests require live external services and are also **deselected** (not just skipped)
in the default `addopts = "-m 'not integration'"` configuration for `aevum-core` and
`aevum-conformance`.

| Service | Tests skipped | Env var required | Test file(s) |
|---|---|---|---|
| PostgreSQL | 9 | `AEVUM_TEST_POSTGRES_DSN` | `test_ledger.py`, `test_pg_consent.py`, `test_pg_store.py` |
| HashiCorp Vault | 3 | `VAULT_ADDR` | `test_vault_transit_signer.py` |

To run integration tests locally:

```bash
# PostgreSQL
AEVUM_TEST_POSTGRES_DSN="postgresql://user:pass@localhost/aevum_test" \
  uv run pytest packages/aevum-store-postgres/ -m integration

# Vault
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-root \
  uv run pytest packages/aevum-core/tests/test_vault_transit_signer.py -m integration
```

Rekor and TSA integration tests (`@pytest.mark.integration` in `test_phase5_rekor.py`
and `test_phase1_tsa.py`) are **deselected** by the default config — they do not appear
in the skipped count. Run them with:

```bash
AEVUM_REKOR_URL=https://your-rekor-instance \
  uv run pytest packages/aevum-core/ -m integration
```

### Bucket C — Explicitly deferred (0 tests)

No tests with stale or unclear skip reasons were found as of v0.7.3.
All `@pytest.mark.skip` uses have valid, current reasons.

### Bucket D — Unclear skip reason (0 tests)

No tests with missing or always-true skip conditions were found.

---

## Deselected tests (10 tests)

Tests marked `@pytest.mark.integration` in `aevum-core` and `aevum-conformance`
are excluded from the default run via `addopts = "-m 'not integration'"`.
These include Rekor anchoring tests and TSA network tests.
They do not appear in the pass or skip counts above.
