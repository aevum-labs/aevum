# CI Errors — Diagnosis and Fix Plan

## Summary

Two CI jobs are currently failing: **Type check (mypy)** and **Tests (pytest)**.
Both share the same root cause. Lint and namespace check both pass.

---

## Root Cause

Three packages have `tests/__init__.py` files:

- `packages/aevum-core/tests/__init__.py`
- `packages/aevum-server/tests/__init__.py`
- `packages/aevum-store-oxigraph/tests/__init__.py`

This makes Python treat each `tests/` directory as a package named `tests`.
When mypy and pytest run from the workspace root they encounter multiple modules
with the same name and break.

---

## Failure 1 — mypy (fatal, zero source checked)

```
packages/aevum-server/tests/__init__.py: error: Duplicate module named "tests"
  (also at "packages/aevum-core/tests/__init__.py")
Found 1 error in 1 file (errors prevented further checking)
```

mypy aborts immediately. **No source code is type-checked at all.**

---

## Failure 2 — pytest (3 collection errors, 0 tests run)

```
ERROR packages/aevum-server/tests
    ModuleNotFoundError: No module named 'tests.conftest'

ERROR packages/aevum-store-oxigraph/tests/test_engine_integration.py
    ModuleNotFoundError: No module named 'tests.test_engine_integration'

ERROR packages/aevum-store-oxigraph/tests/test_store.py
    ModuleNotFoundError: No module named 'tests.test_store'
```

48 test items are discovered but all three packages with `__init__.py` in their
test directory fail to collect. After importing `aevum-core`'s `tests` package
first, Python cannot re-import a different `tests` package for the other two.

---

## Proposed Fix (4 changes)

### Change 1 — Delete the three `__init__.py` files from test directories

| File | Action |
|---|---|
| `packages/aevum-core/tests/__init__.py` | Delete |
| `packages/aevum-server/tests/__init__.py` | Delete |
| `packages/aevum-store-oxigraph/tests/__init__.py` | Delete |

Without `__init__.py`, pytest uses rootdir-relative import (no package name
collision). `conftest.py` is still auto-loaded by pytest — it does not need to
be a package member. Verified: no test file imports from `tests.*`; all imports
are from `aevum.*`, which are installed via `uv sync`.

### Change 2 — Add `explicit_package_bases = true` to root mypy config

**File:** `pyproject.toml` (workspace root), section `[tool.mypy]`

```toml
[tool.mypy]
strict = true
python_version = "3.11"
explicit_package_bases = true   # ← add this
```

This is the correct setting for a monorepo where multiple `src/` directories
feed the same `aevum` namespace package. Without it mypy cannot distinguish
`packages/aevum-core/src` from `packages/aevum-server/src` as separate roots.

---

## Verification (after fix)

```bash
# Namespace check (should still pass)
python scripts/check_namespace.py

# Lint (should still pass)
uv run ruff check .

# Type check (should now complete without "Duplicate module" error)
uv run mypy packages/

# Full test suite (all 48 items should collect and run)
uv run pytest

# Conformance canary
uv run pytest packages/aevum-core/tests/test_canary.py -v --tb=short
```

---

## CI Jobs Not Affected

| Job | Status |
|---|---|
| Lint (ruff) | ✅ Passes today, unaffected by fix |
| Namespace check | ✅ Passes today, unaffected by fix |
| Security (uv audit) | ✅ Scheduled weekly, unaffected |
| Release | ✅ Tag-triggered, unaffected |
| Conformance | ✅ PR-path-filtered, unaffected |
