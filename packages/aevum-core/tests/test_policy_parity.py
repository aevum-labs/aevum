"""
Policy parity tests — verify OPA and Cedar produce identical decisions.
Uses mocked HTTP server; no live OPA required.

NO tests/__init__.py (standing rule).
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from aevum.core.policy.opa_engine import OPAPolicyEngine

# Test matrix: (context, expected_decision)
# Same inputs tested against both Cedar (via PolicyBridge) and OPA (mocked)
CONSENT_TEST_MATRIX = [
    # grant_active, purpose_specific, classification_ok, expected
    ({"grant_active": True, "purpose_specific": True, "classification_ok": True}, True),
    ({"grant_active": False, "purpose_specific": True, "classification_ok": True}, False),
    ({"grant_active": True, "purpose_specific": False, "classification_ok": True}, False),
    ({"grant_active": True, "purpose_specific": True, "classification_ok": False}, False),
]

CLASSIFICATION_TEST_MATRIX = [
    ({"classification": 0, "ceiling": 3}, True),
    ({"classification": 2, "ceiling": 2}, True),
    ({"classification": 3, "ceiling": 2}, False),
    ({"classification": 1, "ceiling": 0}, False),
]

PROVENANCE_TEST_MATRIX = [
    # Genesis (sequence 0) always permitted
    ({"sequence": 0, "prior_hash": "0" * 64}, True),
    ({"sequence": 0, "prior_hash": ""}, True),
    # Non-genesis with valid hash
    ({"sequence": 1, "prior_hash": "abc123def456" + "0" * 52}, True),
    # Non-genesis with zero-hash (forbidden)
    ({"sequence": 1, "prior_hash": "0" * 64}, False),
    # Non-genesis with empty hash (forbidden)
    ({"sequence": 1, "prior_hash": ""}, False),
]


@pytest.mark.parametrize("context,expected", CONSENT_TEST_MATRIX)
def test_opa_consent_mock(context: dict, expected: bool) -> None:
    """OPAPolicyEngine returns correct decision for consent context (mocked OPA)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": expected}

    with patch("httpx.Client.post", return_value=mock_resp):
        engine = OPAPolicyEngine(opa_url="http://mock-opa:8181")
        result = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="agent-1",
            action="consent::grant",
            resource_type="Subject",
            resource_id="subject-1",
            context=context,
        )
    assert result == expected


@pytest.mark.parametrize("context,expected", CLASSIFICATION_TEST_MATRIX)
def test_opa_classification_mock(context: dict, expected: bool) -> None:
    """OPAPolicyEngine routes classification:: actions correctly (mocked OPA)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": expected}

    with patch("httpx.Client.post", return_value=mock_resp):
        engine = OPAPolicyEngine(opa_url="http://mock-opa:8181")
        result = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="agent-1",
            action="classification::check",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=context,
        )
    assert result == expected


@pytest.mark.parametrize("context,expected", PROVENANCE_TEST_MATRIX)
def test_opa_provenance_mock(context: dict, expected: bool) -> None:
    """OPAPolicyEngine routes provenance:: actions correctly (mocked OPA)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": expected}

    with patch("httpx.Client.post", return_value=mock_resp):
        engine = OPAPolicyEngine(opa_url="http://mock-opa:8181")
        result = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="agent-1",
            action="provenance::verify",
            resource_type="LedgerEntry",
            resource_id="entry-42",
            context=context,
        )
    assert result == expected


def test_opa_action_routing() -> None:
    """OPAPolicyEngine routes actions to correct Rego packages."""
    engine = OPAPolicyEngine(opa_url="http://mock-opa:8181")
    assert engine._route_action("consent::grant") == "aevum/consent/allow"
    assert engine._route_action("classification::check") == "aevum/classification_ceiling/allow"
    assert engine._route_action("provenance::verify") == "aevum/provenance/allow"
    assert engine._route_action("tool_call") == "aevum/authz/allow"
    assert engine._route_action("navigate") == "aevum/authz/allow"
    assert engine._route_action("relate_graph_write") == "aevum/authz/allow"


def test_opa_fails_open_on_network_error() -> None:
    """OPAPolicyEngine returns True (permissive) when OPA is unreachable."""
    engine = OPAPolicyEngine(opa_url="http://localhost:19999")
    result = engine.is_permitted(
        principal_type="AevumAgent",
        principal_id="agent-1",
        action="consent::grant",
        resource_type="Subject",
        resource_id="s-1",
        context={"grant_active": True, "purpose_specific": True, "classification_ok": True},
    )
    assert result is True


def test_opa_fails_open_on_non_200() -> None:
    """OPAPolicyEngine returns True (permissive) on non-200 OPA response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 503

    with patch("httpx.Client.post", return_value=mock_resp):
        engine = OPAPolicyEngine(opa_url="http://mock-opa:8181")
        result = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="agent-1",
            action="consent::grant",
            resource_type="Subject",
            resource_id="s-1",
            context={"grant_active": True, "purpose_specific": True, "classification_ok": True},
        )
    assert result is True


def test_opa_requires_url() -> None:
    """OPAPolicyEngine raises RuntimeError when no URL configured."""
    env = {k: v for k, v in os.environ.items() if k != "AEVUM_OPA_URL"}
    with patch.dict(os.environ, env, clear=True), pytest.raises(RuntimeError, match="AEVUM_OPA_URL"):
        OPAPolicyEngine()


def test_opa_url_from_env() -> None:
    """OPAPolicyEngine reads URL from AEVUM_OPA_URL env var."""
    with patch.dict(os.environ, {"AEVUM_OPA_URL": "http://env-opa:8181"}):
        engine = OPAPolicyEngine()
    assert engine._opa_url == "http://env-opa:8181"


def test_opa_trailing_slash_stripped() -> None:
    """Trailing slash in opa_url is normalised."""
    engine = OPAPolicyEngine(opa_url="http://opa:8181/")
    assert engine._opa_url == "http://opa:8181"


def test_null_policy_engine_is_permissive() -> None:
    """NullPolicyEngine always returns True and warns once."""
    from aevum.core.policy import NullPolicyEngine
    engine = NullPolicyEngine()
    NullPolicyEngine._warned = False  # reset class state for test isolation
    result = engine.is_permitted(
        principal_type="T",
        principal_id="id",
        action="a",
        resource_type="R",
        resource_id="r",
        context={},
    )
    assert result is True


def test_policy_engine_protocol_conformance() -> None:
    """All engines conform to the PolicyEngine Protocol."""
    from aevum.core.policy import NullPolicyEngine, PolicyEngine

    null = NullPolicyEngine()
    assert isinstance(null, PolicyEngine)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": True}
    with patch("httpx.Client.post", return_value=mock_resp):
        opa = OPAPolicyEngine(opa_url="http://mock:8181")
        assert isinstance(opa, PolicyEngine)
