"""
Phase 8 verification script.

Checks all three Phase 8 deliverables:
  1. ConsentLedgerProtocol in aevum-core + Engine consent_ledger= kwarg
  2. PostgresStore + PostgresConsentLedger (using FakeConn, no real DB)
  3. OIDC Bearer auth in aevum-server (TestClient, no real IDP)

Run: uv run python scripts/verify_phase08.py
Exit 0 = all checks pass. Exit 1 = at least one failure.
"""

from __future__ import annotations

import sys
import threading
import traceback
from typing import Any

PASS = "✓"
FAIL = "✗"
checks: list[tuple[str, bool, str]] = []


def check(label: str, fn: Any) -> None:
    try:
        result = fn()
        ok = bool(result) if result is not None else True
        checks.append((label, ok, ""))
    except Exception as exc:
        checks.append((label, False, traceback.format_exc()))


# ══ Deliverable 1: ConsentLedgerProtocol + Engine kwarg ═══════════════════════

def _protocol_importable() -> bool:
    from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol  # noqa: F401
    return True


def _protocol_in_package_init() -> bool:
    from aevum.core.protocols import ConsentLedgerProtocol  # noqa: F401
    return True


def _in_memory_ledger_satisfies_protocol() -> bool:
    from aevum.core.consent.ledger import ConsentLedger
    from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
    return isinstance(ConsentLedger(), ConsentLedgerProtocol)


def _engine_accepts_consent_ledger_kwarg() -> bool:
    from aevum.core.consent.ledger import ConsentLedger
    from aevum.core.engine import Engine
    custom_ledger = ConsentLedger()
    engine = Engine(consent_ledger=custom_ledger)
    return engine._consent_ledger is custom_ledger


def _engine_defaults_to_in_memory_when_not_provided() -> bool:
    from aevum.core.consent.ledger import ConsentLedger
    from aevum.core.engine import Engine
    engine = Engine()
    return isinstance(engine._consent_ledger, ConsentLedger)


def _engine_get_active_complication_by_capability() -> bool:
    from aevum.core.engine import Engine
    engine = Engine()
    # No complications installed → should return None
    return engine.get_active_complication_by_capability("oidc-validation") is None


# ══ Deliverable 2: PostgresStore + PostgresConsentLedger ══════════════════════

def _pg_imports() -> bool:
    from aevum.store.postgres import PostgresConsentLedger, PostgresStore  # noqa: F401
    return True


def _pg_store_satisfies_graphstore_protocol() -> bool:
    from unittest.mock import MagicMock
    from aevum.core.protocols.graph_store import GraphStore
    from aevum.store.postgres import PostgresStore
    mock_conn = MagicMock()
    store = PostgresStore(mock_conn)
    return isinstance(store, GraphStore)


def _pg_consent_satisfies_protocol() -> bool:
    from unittest.mock import MagicMock
    from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
    from aevum.store.postgres import PostgresConsentLedger
    mock_conn = MagicMock()
    consent = PostgresConsentLedger(mock_conn)
    return isinstance(consent, ConsentLedgerProtocol)


def _pg_engine_integration() -> bool:
    """Engine can be constructed with Postgres-backed store and consent ledger."""
    from unittest.mock import MagicMock
    from aevum.core.engine import Engine
    from aevum.store.postgres import PostgresConsentLedger, PostgresStore
    mock_conn = MagicMock()
    store = PostgresStore(mock_conn)
    consent = PostgresConsentLedger(mock_conn)
    engine = Engine(graph_store=store, consent_ledger=consent)
    return engine is not None


def _pg_store_fakeconn_store_and_get() -> bool:
    """FakeConn-backed store can store and retrieve an entity."""
    import sys
    sys.path.insert(0, "packages/aevum-store-postgres/tests")
    from conftest import FakeConn
    from aevum.store.postgres import PostgresStore
    conn = FakeConn()
    store = PostgresStore(conn)
    store.store_entity("verify-e1", {"content": "hello"})
    result = store.get_entity("verify-e1")
    sys.path.pop(0)
    return result is not None and result["content"] == "hello"


def _pg_consent_fakeconn_add_and_check() -> bool:
    """FakeConn-backed consent ledger can add and verify a grant."""
    import sys
    sys.path.insert(0, "packages/aevum-store-postgres/tests")
    from conftest import FakeConn
    from aevum.core.consent.models import ConsentGrant
    from aevum.store.postgres import PostgresConsentLedger
    conn = FakeConn()
    consent = PostgresConsentLedger(conn)
    grant = ConsentGrant(
        grant_id="verify-g1", subject_id="s1", grantee_id="actor",
        operations=["ingest"], purpose="verify-phase08", classification_max=1,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    )
    consent.add_grant(grant)
    result = consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")
    sys.path.pop(0)
    return result


def _pg_migrate_importable() -> bool:
    from aevum.store.postgres.migrate import migrate_from_oxigraph  # noqa: F401
    return True


def _pg_schema_importable() -> bool:
    from aevum.store.postgres.schema import initialize_schema  # noqa: F401
    return True


def _pg_shared_lock_pattern() -> bool:
    """Store and consent ledger can share a lock (the intended usage pattern)."""
    import sys
    sys.path.insert(0, "packages/aevum-store-postgres/tests")
    from conftest import FakeConn
    from aevum.store.postgres import PostgresConsentLedger, PostgresStore
    conn = FakeConn()
    lock = threading.Lock()
    store = PostgresStore(conn, lock)
    consent = PostgresConsentLedger(conn, lock)
    result = store._lock is consent._lock
    sys.path.pop(0)
    return result


# ══ Deliverable 3: OIDC Bearer auth ══════════════════════════════════════════

def _oidc_bearer_without_complication_returns_401() -> bool:
    """Fail-closed: no OIDC complication → Bearer token rejected."""
    from aevum.core.engine import Engine
    from fastapi.testclient import TestClient
    from aevum.server.app import create_app
    from aevum.server.core.config import Settings
    app = create_app(engine=Engine(), settings=Settings(api_key="k", otel_enabled=False))
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get(
        "/v1/replay/urn:aevum:audit:00000000-0000-7000-8000-000000000001",
        headers={"Authorization": "Bearer some-token"},
    )
    return r.status_code == 401


def _oidc_bearer_with_mock_complication_resolves_actor() -> bool:
    """Valid Bearer token resolves actor via installed mock OIDC complication."""
    from typing import Any as TypingAny
    from aevum.core.consent.models import ConsentGrant
    from aevum.core.engine import Engine
    from fastapi.testclient import TestClient
    from aevum.server.app import create_app
    from aevum.server.core.config import Settings

    class _MockOidc:
        name = "oidc"
        version = "0.1.0"
        capabilities = ["oidc-validation", "actor-resolution"]

        async def run(self, ctx: dict[str, TypingAny], payload: dict[str, TypingAny]) -> dict[str, TypingAny]:
            token = ctx.get("metadata", {}).get("bearer_token", "")
            if token == "valid":
                return {"oidc_validated": True, "resolved_actor": "oidc-actor", "resolved_classification": 0}
            return {"oidc_validated": False, "reason": "bad token"}

        def manifest(self) -> dict[str, TypingAny]:
            return {
                "name": "oidc", "version": "0.1.0",
                "capabilities": list(self.capabilities),
                "classification_max": 0, "functions": ["query"],
                "auth": {"scopes_required": [], "public_key": None},
                "schema_version": "1.0",
                "description": "mock oidc",
            }

        def health(self) -> bool:
            return True

    engine = Engine()
    engine.install_complication(_MockOidc(), auto_approve=True)
    engine.add_consent_grant(ConsentGrant(
        grant_id="v-g", subject_id="s", grantee_id="oidc-actor",
        operations=["ingest", "query", "replay", "export"],
        purpose="verify-phase08", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    app = create_app(engine=engine, settings=Settings(api_key="k", otel_enabled=False))
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/ingest",
        json={
            "data": {"x": 1},
            "provenance": {
                "source_id": "src",
                "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
                "chain_of_custody": ["src"], "classification": 0, "model_id": None,
            },
            "purpose": "verify-phase08",
            "subject_id": "s",
        },
        headers={"Authorization": "Bearer valid"},
    )
    return r.status_code == 200 and r.json().get("status") == "ok"


def _oidc_invalid_bearer_returns_401() -> bool:
    from typing import Any as TypingAny
    from aevum.core.engine import Engine
    from fastapi.testclient import TestClient
    from aevum.server.app import create_app
    from aevum.server.core.config import Settings

    class _MockOidc:
        name = "oidc"
        version = "0.1.0"
        capabilities = ["oidc-validation", "actor-resolution"]

        async def run(self, ctx: dict[str, TypingAny], p: dict[str, TypingAny]) -> dict[str, TypingAny]:
            return {"oidc_validated": False, "reason": "always reject"}

        def manifest(self) -> dict[str, TypingAny]:
            return {
                "name": "oidc", "version": "0.1.0", "capabilities": list(self.capabilities),
                "classification_max": 0, "functions": ["query"],
                "auth": {"scopes_required": [], "public_key": None},
                "schema_version": "1.0", "description": "mock",
            }

        def health(self) -> bool:
            return True

    engine = Engine()
    engine.install_complication(_MockOidc(), auto_approve=True)
    app = create_app(engine=engine, settings=Settings(api_key="k", otel_enabled=False))
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get(
        "/v1/replay/urn:aevum:audit:00000000-0000-7000-8000-000000000001",
        headers={"Authorization": "Bearer bad-token"},
    )
    return r.status_code == 401


def _api_key_still_works_when_oidc_active() -> bool:
    from typing import Any as TypingAny
    from aevum.core.consent.models import ConsentGrant
    from aevum.core.engine import Engine
    from fastapi.testclient import TestClient
    from aevum.server.app import create_app
    from aevum.server.core.config import Settings

    class _MockOidc:
        name = "oidc"
        version = "0.1.0"
        capabilities = ["oidc-validation", "actor-resolution"]

        async def run(self, ctx: dict[str, TypingAny], p: dict[str, TypingAny]) -> dict[str, TypingAny]:
            return {"oidc_validated": True, "resolved_actor": "oidc-actor", "resolved_classification": 0}

        def manifest(self) -> dict[str, TypingAny]:
            return {
                "name": "oidc", "version": "0.1.0", "capabilities": list(self.capabilities),
                "classification_max": 0, "functions": ["query"],
                "auth": {"scopes_required": [], "public_key": None},
                "schema_version": "1.0", "description": "mock",
            }

        def health(self) -> bool:
            return True

    engine = Engine()
    engine.install_complication(_MockOidc(), auto_approve=True)
    engine.add_consent_grant(ConsentGrant(
        grant_id="apikey-g", subject_id="s2", grantee_id="my-api-key",
        operations=["ingest", "query", "replay", "export"],
        purpose="verify-phase08-apikey", classification_max=3,
        granted_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
    ))
    app = create_app(engine=engine, settings=Settings(api_key="my-api-key", otel_enabled=False))
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/v1/ingest",
        json={
            "data": {"x": 1},
            "provenance": {
                "source_id": "src",
                "ingest_audit_id": "urn:aevum:audit:00000000-0000-7000-8000-000000000001",
                "chain_of_custody": ["src"], "classification": 0, "model_id": None,
            },
            "purpose": "verify-phase08-apikey",
            "subject_id": "s2",
        },
        headers={"X-Aevum-Key": "my-api-key"},
    )
    return r.status_code == 200 and r.json().get("status") == "ok"


# ══ Register all checks ═══════════════════════════════════════════════════════

CHECKS = [
    # Deliverable 1
    ("D1-01: ConsentLedgerProtocol importable from aevum.core.protocols.consent_ledger", _protocol_importable),
    ("D1-02: ConsentLedgerProtocol exported from aevum.core.protocols", _protocol_in_package_init),
    ("D1-03: InMemoryConsentLedger satisfies ConsentLedgerProtocol", _in_memory_ledger_satisfies_protocol),
    ("D1-04: Engine accepts consent_ledger= kwarg", _engine_accepts_consent_ledger_kwarg),
    ("D1-05: Engine defaults to InMemoryConsentLedger when not provided", _engine_defaults_to_in_memory_when_not_provided),
    ("D1-06: Engine.get_active_complication_by_capability() returns None when empty", _engine_get_active_complication_by_capability),
    # Deliverable 2
    ("D2-01: aevum.store.postgres imports (PostgresStore, PostgresConsentLedger)", _pg_imports),
    ("D2-02: PostgresStore satisfies GraphStore Protocol", _pg_store_satisfies_graphstore_protocol),
    ("D2-03: PostgresConsentLedger satisfies ConsentLedgerProtocol", _pg_consent_satisfies_protocol),
    ("D2-04: Engine can be constructed with Postgres-backed store + consent", _pg_engine_integration),
    ("D2-05: FakeConn store_entity + get_entity round-trip", _pg_store_fakeconn_store_and_get),
    ("D2-06: FakeConn consent add_grant + has_consent", _pg_consent_fakeconn_add_and_check),
    ("D2-07: migrate_from_oxigraph importable", _pg_migrate_importable),
    ("D2-08: initialize_schema importable", _pg_schema_importable),
    ("D2-09: Shared lock pattern — store and consent share same Lock", _pg_shared_lock_pattern),
    # Deliverable 3
    ("D3-01: Bearer without OIDC complication → 401 (fail-closed)", _oidc_bearer_without_complication_returns_401),
    ("D3-02: Valid Bearer + mock OIDC → actor resolved + ingest succeeds", _oidc_bearer_with_mock_complication_resolves_actor),
    ("D3-03: Invalid Bearer + mock OIDC → 401", _oidc_invalid_bearer_returns_401),
    ("D3-04: API key still works when OIDC complication is active", _api_key_still_works_when_oidc_active),
]


def main() -> int:
    print(f"\nPhase 8 verification — {len(CHECKS)} checks\n")
    for label, fn in CHECKS:
        check(label, fn)

    passed = sum(1 for _, ok, _ in checks if ok)
    failed = len(checks) - passed

    for label, ok, tb in checks:
        icon = PASS if ok else FAIL
        print(f"  {icon}  {label}")
        if not ok and tb:
            for line in tb.strip().splitlines():
                print(f"       {line}")

    print(f"\n{passed}/{len(checks)} checks passed")
    if failed:
        print(f"{failed} failed — Phase 8 NOT complete")
        return 1
    print("Phase 8 complete ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
