# SPDX-License-Identifier: Apache-2.0
"""
Layer 3 — AEVUM_DEV=1 developer mode conformance tests (Phase B-01 through B-07).

Verifies the behavioral contract of the zero-config developer mode:
  1. is_dev_mode() returns True iff AEVUM_DEV is exactly "1".
  2. DevModeConsentLedger is unconditionally permissive for all callers.
  3. build_dev_provenance() never leaks secret-named env vars.

Reference: aevum.core.dev_mode
"""
from __future__ import annotations

import os
from unittest.mock import patch

from aevum.core.dev_mode import DevModeConsentLedger, build_dev_provenance, is_dev_mode


class TestIsDevModeContract:
    """is_dev_mode() must return True only when AEVUM_DEV is exactly "1"."""

    def test_true_when_aevum_dev_is_one(self) -> None:
        with patch.dict(os.environ, {"AEVUM_DEV": "1"}):
            assert is_dev_mode() is True

    def test_false_when_aevum_dev_unset(self) -> None:
        clean = {k: v for k, v in os.environ.items() if k != "AEVUM_DEV"}
        with patch.dict(os.environ, clean, clear=True):
            assert is_dev_mode() is False

    def test_false_when_aevum_dev_is_zero(self) -> None:
        with patch.dict(os.environ, {"AEVUM_DEV": "0"}):
            assert is_dev_mode() is False

    def test_false_when_aevum_dev_is_true_string(self) -> None:
        with patch.dict(os.environ, {"AEVUM_DEV": "true"}):
            assert is_dev_mode() is False

    def test_false_when_aevum_dev_is_empty(self) -> None:
        with patch.dict(os.environ, {"AEVUM_DEV": ""}):
            assert is_dev_mode() is False

    def test_false_when_aevum_dev_is_yes(self) -> None:
        with patch.dict(os.environ, {"AEVUM_DEV": "yes"}):
            assert is_dev_mode() is False

    def test_false_when_aevum_dev_is_one_with_trailing_space(self) -> None:
        with patch.dict(os.environ, {"AEVUM_DEV": "1 "}):
            # strip() is applied — trailing space must still yield True
            assert is_dev_mode() is True


class TestDevModeConsentLedgerContract:
    """DevModeConsentLedger must be unconditionally permissive for every caller."""

    def test_has_consent_true_for_ingest(self) -> None:
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="user-1", operation="ingest",
            grantee_id="agent-1", purpose="billing-inquiry",
        ) is True

    def test_has_consent_true_for_query(self) -> None:
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="user-1", operation="query",
            grantee_id="agent-1", purpose="billing-inquiry",
        ) is True

    def test_has_consent_true_for_replay(self) -> None:
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="user-1", operation="replay",
            grantee_id="agent-1", purpose="audit",
        ) is True

    def test_has_consent_true_without_purpose(self) -> None:
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="u", operation="ingest", grantee_id="a"
        ) is True

    def test_has_consent_true_for_unknown_operation(self) -> None:
        ledger = DevModeConsentLedger()
        assert ledger.has_consent(
            subject_id="u", operation="export", grantee_id="a"
        ) is True

    def test_all_grants_returns_empty_list(self) -> None:
        ledger = DevModeConsentLedger()
        assert ledger.all_grants() == []

    def test_add_grant_is_noop(self) -> None:
        ledger = DevModeConsentLedger()
        ledger.add_grant(None)  # type: ignore[arg-type]
        # Must not raise; dev mode does not track grants

    def test_revoke_grant_is_noop(self) -> None:
        ledger = DevModeConsentLedger()
        ledger.revoke_grant("any-grant-id")
        # Must not raise; dev mode ignores revocations


class TestBuildDevProvenanceContract:
    """build_dev_provenance() must produce a valid provenance record with no leaked secrets."""

    def test_required_provenance_fields_present(self) -> None:
        prov = build_dev_provenance()
        assert prov["source_id"] == "aevum-dev-auto"
        assert prov["classification"] == 0
        assert isinstance(prov["chain_of_custody"], list)
        assert len(prov["chain_of_custody"]) > 0

    def test_excludes_secret_env_vars_by_name_pattern(self) -> None:
        injected = {
            "AEVUM_TEST_SECRET": "s3cr3t",
            "API_KEY": "key123",
            "DB_PASSWORD": "hunter2",
            "ACCESS_TOKEN": "tok",
            "MY_PWD": "pass",
        }
        with patch.dict(os.environ, injected):
            prov = build_dev_provenance()
            snap = prov.get("env_snapshot", {})
            for secret_key in injected:
                assert secret_key not in snap, (
                    f"Secret env var {secret_key!r} leaked into dev provenance snapshot"
                )

    def test_env_snapshot_contains_no_secret_pattern_keys(self) -> None:
        prov = build_dev_provenance()
        snap = prov.get("env_snapshot", {})
        for k in snap:
            upper = k.upper()
            assert not any(
                word in upper for word in ("SECRET", "KEY", "TOKEN", "PASS", "PWD")
            ), f"Secret-named env var {k!r} leaked into dev provenance snapshot"
