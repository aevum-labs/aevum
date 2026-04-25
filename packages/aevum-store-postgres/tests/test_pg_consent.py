"""
Tests for PostgresConsentLedger — ConsentLedgerProtocol conformance.

Fake-conn tests run without a real database (use the fake_store_parts fixture).
Integration tests skip unless AEVUM_TEST_POSTGRES_DSN is set.
"""

from __future__ import annotations

from typing import Any

from aevum.core.consent.models import ConsentGrant
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol


def _grant(**overrides: object) -> ConsentGrant:
    defaults: dict = {
        "grant_id": "g1",
        "subject_id": "s1",
        "grantee_id": "actor",
        "operations": ["ingest", "query", "replay", "export"],
        "purpose": "unit-testing",
        "classification_max": 3,
        "granted_at": "2026-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
    }
    defaults.update(overrides)
    return ConsentGrant(**defaults)


# ── Protocol conformance ──────────────────────────────────────────────────────

def test_satisfies_consent_ledger_protocol(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    assert isinstance(consent, ConsentLedgerProtocol)


# ── Unit tests (FakeConn) ─────────────────────────────────────────────────────

def test_add_and_has_consent(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant())
    assert consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_no_grant_returns_false(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    assert not consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_revoke_grant(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant(grant_id="rev1"))
    consent.revoke_grant("rev1")
    assert not consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_operation_not_in_grant_returns_false(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant(operations=["ingest"]))
    assert not consent.has_consent(subject_id="s1", operation="query", grantee_id="actor")


def test_expired_grant_returns_false(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant(expires_at="2020-01-01T00:00:00Z"))
    assert not consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_wrong_subject_returns_false(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant(subject_id="other"))
    assert not consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_wrong_grantee_returns_false(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant(grantee_id="someone-else"))
    assert not consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_all_grants_empty(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    assert consent.all_grants() == []


def test_all_grants_returns_added(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant())
    grants = consent.all_grants()
    assert len(grants) == 1
    assert grants[0].grant_id == "g1"


def test_all_grants_includes_revoked(fake_store_parts: Any) -> None:
    _, consent, _ = fake_store_parts
    consent.add_grant(_grant(grant_id="rev"))
    consent.revoke_grant("rev")
    grants = consent.all_grants()
    assert len(grants) == 1
    assert grants[0].revocation_status == "revoked"


# ── Integration tests (real Postgres) ────────────────────────────────────────

def test_pg_add_and_has_consent_real(pg_consent: Any) -> None:
    assert isinstance(pg_consent, ConsentLedgerProtocol)
    pg_consent.add_grant(_grant(grant_id="pg-g1"))
    assert pg_consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_pg_revoke_real(pg_consent: Any) -> None:
    pg_consent.add_grant(_grant(grant_id="pg-rev"))
    pg_consent.revoke_grant("pg-rev")
    assert not pg_consent.has_consent(subject_id="s1", operation="ingest", grantee_id="actor")


def test_pg_all_grants_real(pg_consent: Any) -> None:
    pg_consent.add_grant(_grant(grant_id="pg-all"))
    grants = pg_consent.all_grants()
    assert any(g.grant_id == "pg-all" for g in grants)
