"""
Tests for the Cedar policy bridge in PolicyBridge.
cedarpy must be installed for real Cedar evaluation; falls back to permissive if not.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import pytest

from aevum.core.policy.bridge import PolicyBridge, _is_purpose_specific


class TestPurposeSpecificity:
    def test_generic_purposes_rejected(self) -> None:
        for bad in ("any", "all", "analytics", "all purposes", "any purpose", ""):
            assert _is_purpose_specific(bad) is False, f"Expected {bad!r} to be non-specific"

    def test_specific_purposes_accepted(self) -> None:
        for good in ("quarterly-fraud-detection", "gdpr-audit-2026", "onboarding-survey"):
            assert _is_purpose_specific(good) is True, f"Expected {good!r} to be specific"


class TestPolicyBridgePermissive:
    """These tests always pass regardless of cedarpy availability."""

    def test_infrastructure_always_permits(self) -> None:
        bridge = PolicyBridge()
        assert bridge.evaluate_infrastructure(actor="a", operation="query", resource={}) is True

    def test_consent_denied_when_grant_inactive(self) -> None:
        bridge = PolicyBridge()
        result = bridge.evaluate_consent(
            subject_id="s1", operation="query", grantee_id="actor",
            purpose="specific-purpose", classification=0,
            grant_active=False,  # No active grant
            classification_max=3,
        )
        assert result is False

    def test_consent_denied_when_classification_exceeded(self) -> None:
        bridge = PolicyBridge()
        result = bridge.evaluate_consent(
            subject_id="s1", operation="query", grantee_id="actor",
            purpose="specific-purpose", classification=3,
            grant_active=True,
            classification_max=1,  # Too low for classification=3
        )
        assert result is False

    def test_consent_denied_for_generic_purpose(self) -> None:
        bridge = PolicyBridge()
        result = bridge.evaluate_consent(
            subject_id="s1", operation="query", grantee_id="actor",
            purpose="analytics",  # Too generic
            classification=0,
            grant_active=True,
            classification_max=3,
        )
        assert result is False


class TestPolicyBridgeCedar:
    """These tests run Cedar evaluation. Skipped if cedarpy not installed."""

    @pytest.fixture
    def cedar_bridge(self) -> PolicyBridge:
        pytest.importorskip("cedarpy", reason="cedarpy not installed")
        return PolicyBridge()

    def test_cedar_permits_valid_request(self, cedar_bridge: PolicyBridge) -> None:
        # cedarpy 4.x: request is a plain dict, Decision is an enum
        from cedarpy import Decision  # noqa: F401 -- confirms import works
        result = cedar_bridge.evaluate_consent(
            subject_id="subject-1", operation="query", grantee_id="actor-1",
            purpose="quarterly-compliance-check", classification=0,
            grant_active=True, classification_max=3,
        )
        assert result is True

    def test_cedar_denies_inactive_grant(self, cedar_bridge: PolicyBridge) -> None:
        result = cedar_bridge.evaluate_consent(
            subject_id="s1", operation="query", grantee_id="a",
            purpose="quarterly-check", classification=0,
            grant_active=False, classification_max=3,
        )
        assert result is False

    def test_cedar_denies_generic_purpose(self, cedar_bridge: PolicyBridge) -> None:
        result = cedar_bridge.evaluate_consent(
            subject_id="s1", operation="query", grantee_id="a",
            purpose="any", classification=0,
            grant_active=True, classification_max=3,
        )
        assert result is False
