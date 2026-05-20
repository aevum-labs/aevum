# SPDX-License-Identifier: Apache-2.0
"""Tests for AEVUM_DEV=1 zero-config developer mode."""

from __future__ import annotations

import logging
import os

import pytest

from aevum.core.dev_mode import (
    DevModeConsentLedger,
    build_dev_provenance,
    is_dev_mode,
    warn_dev_startup,
)


# ── is_dev_mode() ─────────────────────────────────────────────────────────────

class TestIsDevMode:
    def test_returns_true_when_set_to_1(self, monkeypatch):
        monkeypatch.setenv("AEVUM_DEV", "1")
        assert is_dev_mode() is True

    def test_returns_false_when_unset(self, monkeypatch):
        monkeypatch.delenv("AEVUM_DEV", raising=False)
        assert is_dev_mode() is False

    def test_returns_false_when_set_to_0(self, monkeypatch):
        monkeypatch.setenv("AEVUM_DEV", "0")
        assert is_dev_mode() is False

    def test_returns_false_when_set_to_true_string(self, monkeypatch):
        monkeypatch.setenv("AEVUM_DEV", "true")
        assert is_dev_mode() is False

    def test_returns_false_when_empty(self, monkeypatch):
        monkeypatch.setenv("AEVUM_DEV", "")
        assert is_dev_mode() is False


# ── DevModeConsentLedger ───────────────────────────────────────────────────────

class TestDevModeConsentLedger:
    def test_has_consent_always_true(self):
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="any-subject",
            operation="ingest",
            grantee_id="any-agent",
        ) is True

    def test_has_consent_for_unknown_subject(self):
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="nobody",
            operation="query",
            grantee_id="nobody",
        ) is True

    def test_add_grant_is_noop(self):
        from aevum.core.consent.models import ConsentGrant
        ledger = DevModeConsentLedger()
        grant = ConsentGrant(
            grant_id="g1",
            subject_id="alice",
            grantee_id="agent",
            operations=["ingest"],
            purpose="test",
            classification_max=0,
            granted_at="2026-01-01T00:00:00Z",
            expires_at="2030-01-01T00:00:00Z",
        )
        ledger.add_grant(grant)  # no error
        assert ledger.has_consent(subject_id="alice", operation="ingest", grantee_id="agent") is True

    def test_revoke_grant_is_noop(self):
        ledger = DevModeConsentLedger()
        ledger.revoke_grant("any-grant-id")  # no error
        assert ledger.has_consent(
            subject_id="alice", operation="ingest", grantee_id="agent"
        ) is True

    def test_all_grants_returns_empty(self):
        ledger = DevModeConsentLedger()
        assert ledger.all_grants() == []


# ── build_dev_provenance() ────────────────────────────────────────────────────

class TestBuildDevProvenance:
    def test_has_required_fields(self):
        prov = build_dev_provenance()
        assert prov["source_id"] == "aevum-dev-auto"
        assert "hostname" in prov
        assert "python_version" in prov
        assert "git_commit" in prov

    def test_excludes_secret_env_vars(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET_KEY", "do-not-include")
        monkeypatch.setenv("DATABASE_PASSWORD", "also-secret")
        monkeypatch.setenv("VAULT_TOKEN", "vault-tok")
        monkeypatch.setenv("SAFE_VAR", "include-me")
        prov = build_dev_provenance()
        env = prov.get("env_snapshot", {})
        assert "MY_SECRET_KEY" not in env
        assert "DATABASE_PASSWORD" not in env
        assert "VAULT_TOKEN" not in env
        # SAFE_VAR should be included
        assert "SAFE_VAR" in env

    def test_chain_of_custody_set(self):
        prov = build_dev_provenance()
        assert prov["chain_of_custody"] == ["aevum-dev-auto"]

    def test_classification_zero(self):
        prov = build_dev_provenance()
        assert prov["classification"] == 0


# ── warn_dev_startup() ────────────────────────────────────────────────────────

class TestWarnDevStartup:
    def test_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="aevum.dev"):
            warn_dev_startup()
        assert any("AEVUM_DEV" in r.message for r in caplog.records)

    def test_mentions_dev_mode(self, caplog):
        with caplog.at_level(logging.WARNING, logger="aevum.dev"):
            warn_dev_startup()
        full_output = " ".join(r.message for r in caplog.records)
        assert "PRODUCTION" in full_output or "DEVELOPER MODE" in full_output


# ── Engine integration tests ──────────────────────────────────────────────────

class TestEngineDevMode:
    def test_dev_mode_engine_no_consent_needed(self, monkeypatch, caplog):
        """AEVUM_DEV=1: ingest succeeds without explicit consent grants."""
        monkeypatch.setenv("AEVUM_DEV", "1")
        with caplog.at_level(logging.WARNING, logger="aevum.dev"):
            from aevum.core.engine import Engine
            engine = Engine()

        result = engine.ingest(
            data={"note": "dev mode test"},
            provenance={
                "source_id": "test",
                "chain_of_custody": ["test"],
                "classification": 0,
            },
            purpose="dev-test",
            subject_id="user-dev",
            actor="dev-agent",
        )
        assert result.status == "ok", f"Expected ok, got {result.status!r}: {result}"
        assert any("AEVUM_DEV" in r.message for r in caplog.records)

    def test_dev_mode_off_consent_required(self, monkeypatch):
        """AEVUM_DEV unset: ingest fails without consent grant (Barrier 3)."""
        monkeypatch.delenv("AEVUM_DEV", raising=False)
        from aevum.core.engine import Engine
        engine = Engine()
        result = engine.ingest(
            data={"note": "no consent"},
            provenance={
                "source_id": "test",
                "chain_of_custody": ["test"],
                "classification": 0,
            },
            purpose="prod-test",
            subject_id="user-1",
            actor="agent-1",
        )
        assert result.status == "error"
        assert (result.data or {}).get("error_code") == "consent_required"

    def test_dev_mode_zero_consent_required(self, monkeypatch):
        """AEVUM_DEV=0: same as unset."""
        monkeypatch.setenv("AEVUM_DEV", "0")
        from aevum.core.engine import Engine
        engine = Engine()
        result = engine.ingest(
            data={"note": "no consent"},
            provenance={
                "source_id": "test",
                "chain_of_custody": ["test"],
                "classification": 0,
            },
            purpose="prod-test",
            subject_id="user-1",
            actor="agent-1",
        )
        assert result.status == "error"
        assert (result.data or {}).get("error_code") == "consent_required"

    def test_dev_mode_uses_null_policy_engine(self, monkeypatch):
        """AEVUM_DEV=1: policy engine is NullPolicyEngine."""
        monkeypatch.setenv("AEVUM_DEV", "1")
        from aevum.core.engine import Engine
        from aevum.core.policy import NullPolicyEngine
        engine = Engine()
        assert isinstance(engine._policy_engine, NullPolicyEngine)

    def test_dev_mode_sigchain_intact(self, monkeypatch):
        """AEVUM_DEV=1: sigchain remains verifiable."""
        monkeypatch.setenv("AEVUM_DEV", "1")
        from aevum.core.engine import Engine
        engine = Engine()
        engine.ingest(
            data={"note": "check chain"},
            provenance={"source_id": "t", "chain_of_custody": ["t"], "classification": 0},
            purpose="test",
            subject_id="u1",
            actor="a1",
        )
        assert engine.verify_sigchain() is True
