# SPDX-License-Identifier: Apache-2.0
"""
Tests for aevum-maintainer Phases 3 and 4:
  Track A — A2A task issuance on consent approval
  Track B — Replay endpoint
  Track C — Rekor anchoring on approval
  Track D — Break-glass endpoint
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

if TYPE_CHECKING:
    from aevum.core.engine import Engine
    from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTION_DESC = "Deploy security patch to production systems"
_APPROVAL_BODY = {
    "acknowledged_intent": "Applying CVE-2026-1234 patch to dependency X",
    "acknowledged_blast_radius": "Could break API clients using deprecated field",
    "acknowledged_rollback": "git revert + redeploy takes under 5 minutes",
    "reviewer_id": "neo",
}


def _create_review(client: TestClient, action_type: str = "maintenance-scan") -> str:
    resp = client.post(
        "/v1/consent/review",
        json={
            "action_description": _ACTION_DESC,
            "action_type": action_type,
            "payload": {"target": "prod"},
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["review_id"]


def _approve(client: TestClient, review_id: str) -> dict:
    resp = client.post(
        "/v1/consent/approve",
        json={"review_id": review_id, **_APPROVAL_BODY},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ===========================================================================
# Track A — A2A task issuance
# ===========================================================================


def test_a2a_task_skipped_when_no_agent_url(client: TestClient) -> None:
    """No AEVUM_AGENT_URL set → task issuance silently skipped, approval succeeds."""
    env = {k: v for k, v in os.environ.items() if k != "AEVUM_AGENT_URL"}
    with patch.dict(os.environ, env, clear=True):
        review_id = _create_review(client)
        resp = client.post(
            "/v1/consent/approve",
            json={"review_id": review_id, **_APPROVAL_BODY},
        )
    assert resp.status_code == 200
    assert resp.json()["audit_id"].startswith("urn:aevum:audit:")


def test_a2a_task_issued_when_agent_url_set(client: TestClient) -> None:
    """When AEVUM_AGENT_URL is set, issue_a2a_task is called with correct args."""
    review_id = _create_review(client, action_type="maintenance-scan")
    with patch(
        "aevum_maintainer.server.issue_a2a_task",
        new_callable=AsyncMock,
        return_value={"result": {"id": "task-123", "status": {"state": "SUBMITTED"}}},
    ) as mock_issue, patch.dict(os.environ, {"AEVUM_AGENT_URL": "http://agent:8080/tasks"}):
        resp = client.post(
            "/v1/consent/approve",
            json={"review_id": review_id, **_APPROVAL_BODY},
        )
    assert resp.status_code == 200
    mock_issue.assert_awaited_once()
    call_kwargs = mock_issue.call_args.kwargs
    assert call_kwargs["action_type"] == "maintenance-scan"
    assert call_kwargs["agent_url"] == "http://agent:8080/tasks"
    assert call_kwargs["correlation_id"].startswith("urn:aevum:audit:")


@pytest.mark.asyncio
async def test_a2a_unknown_action_type_returns_none() -> None:
    """Unknown action_type logs a warning and returns None without raising."""
    from aevum_maintainer.a2a_tasks import issue_a2a_task

    result = await issue_a2a_task(
        action_type="totally-unknown",
        payload={},
        agent_url="http://agent:8080/tasks",
        correlation_id="test-id",
    )
    assert result is None


@pytest.mark.asyncio
async def test_a2a_network_failure_returns_none() -> None:
    """Network failure returns None (fail-open) without raising."""
    import httpx
    from aevum_maintainer.a2a_tasks import issue_a2a_task

    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("down")):
        result = await issue_a2a_task(
            action_type="maintenance-scan",
            payload={},
            agent_url="http://agent:8080/tasks",
            correlation_id="test-id",
        )
    assert result is None


def test_a2a_review_stores_action_type_in_pending(client: TestClient, engine: Engine) -> None:
    """review endpoint stores action_type so approval can forward it to A2A."""
    review_id = _create_review(client, action_type="compliance-pack")
    # Peek at the pending reviews via the approval flow
    with patch(
        "aevum_maintainer.server.issue_a2a_task",
        new_callable=AsyncMock,
        return_value=None,
    ) as mock_issue, patch.dict(os.environ, {"AEVUM_AGENT_URL": "http://agent/tasks"}):
        resp = client.post(
            "/v1/consent/approve",
            json={"review_id": review_id, **_APPROVAL_BODY},
        )
    assert resp.status_code == 200
    call_kwargs = mock_issue.call_args.kwargs
    assert call_kwargs["action_type"] == "compliance-pack"


# ===========================================================================
# Track B — Replay endpoint
# ===========================================================================


def test_replay_known_audit_id_returns_200(client: TestClient, engine: Engine) -> None:
    """Valid audit_id from a review event can be replayed successfully."""
    review_resp = client.post(
        "/v1/consent/review",
        json={"action_description": _ACTION_DESC},
    )
    assert review_resp.status_code == 200
    audit_id = review_resp.json()["audit_id"]

    replay_resp = client.post(f"/v1/replay/{audit_id}")
    assert replay_resp.status_code == 200, replay_resp.text
    body = replay_resp.json()
    assert body["audit_id"] == audit_id
    assert "reconstructed_at" in body
    assert "state" in body


def test_replay_unknown_audit_id_returns_404(client: TestClient) -> None:
    """Unknown audit_id returns 404."""
    resp = client.post("/v1/replay/urn:aevum:audit:does-not-exist")
    assert resp.status_code == 404


def test_replay_returns_original_payload(client: TestClient, engine: Engine) -> None:
    """Replayed state contains the original event payload."""
    review_resp = client.post(
        "/v1/consent/review",
        json={"action_description": _ACTION_DESC},
    )
    audit_id = review_resp.json()["audit_id"]

    replay_resp = client.post(f"/v1/replay/{audit_id}")
    assert replay_resp.status_code == 200
    state = replay_resp.json()["state"]
    # replayed_payload is nested inside state
    assert "replayed_payload" in state


# ===========================================================================
# Track C — Rekor anchoring
# ===========================================================================


def test_rekor_anchor_called_on_approval(client: TestClient) -> None:
    """_try_anchor_sigchain is called when consent is approved."""
    review_id = _create_review(client)
    with patch("aevum_maintainer.server._try_anchor_sigchain") as mock_anchor:
        resp = client.post(
            "/v1/consent/approve",
            json={"review_id": review_id, **_APPROVAL_BODY},
        )
    assert resp.status_code == 200
    mock_anchor.assert_called_once()
    call_args = mock_anchor.call_args
    assert call_args.args[1].startswith("urn:aevum:audit:")


def test_rekor_anchor_failure_does_not_block_approval(client: TestClient) -> None:
    """A Rekor failure must not prevent the approval from succeeding."""
    review_id = _create_review(client)
    with patch(
        "aevum_maintainer.server._try_anchor_sigchain",
        side_effect=RuntimeError("unexpected"),
    ):
        resp = client.post(
            "/v1/consent/approve",
            json={"review_id": review_id, **_APPROVAL_BODY},
        )
    assert resp.status_code == 200
    assert resp.json()["audit_id"].startswith("urn:aevum:audit:")


def test_try_anchor_sigchain_swallows_exceptions(engine: Engine) -> None:
    """_try_anchor_sigchain never raises regardless of internal failures."""
    from aevum_maintainer.server import _try_anchor_sigchain

    engine._sigchain._prior_hash = "not-a-valid-hex"
    _try_anchor_sigchain(engine, "test-audit-id")  # must not raise


def test_try_anchor_sigchain_with_real_engine(engine: Engine) -> None:
    """_try_anchor_sigchain completes without raising on a real engine (Rekor mocked)."""
    from aevum.core.audit.rekor_anchor import RekorAnchor
    from aevum_maintainer.server import _try_anchor_sigchain

    engine.commit(event_type="consent.approved", payload={"x": 1}, actor="maintainer")

    with patch.object(RekorAnchor, "anchor_chain_root", return_value=None):
        _try_anchor_sigchain(engine, "urn:aevum:audit:test")


# ===========================================================================
# Track D — Break-glass endpoint
# ===========================================================================

_BG_TOKEN = "super-secret-break-glass-token"
_BG_BODY = {
    "reason": "Primary approval system offline — emergency deployment required",
    "requester": "ops-oncall-001",
    "action": "deploy-hotfix",
}


def test_break_glass_valid_token_returns_200(client: TestClient) -> None:
    """Valid break-glass token returns 200 with audit_id."""
    with patch.dict(os.environ, {"AEVUM_BREAK_GLASS_TOKEN": _BG_TOKEN}):
        resp = client.post(
            "/v1/break-glass",
            json=_BG_BODY,
            headers={"X-Break-Glass-Token": _BG_TOKEN},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "break_glass_recorded"
    assert body["audit_id"].startswith("urn:aevum:audit:")
    assert "warning" in body


def test_break_glass_invalid_token_returns_403(client: TestClient) -> None:
    """Invalid break-glass token returns 403."""
    with patch.dict(os.environ, {"AEVUM_BREAK_GLASS_TOKEN": _BG_TOKEN}):
        resp = client.post(
            "/v1/break-glass",
            json=_BG_BODY,
            headers={"X-Break-Glass-Token": "wrong-token"},
        )
    assert resp.status_code == 403


def test_break_glass_missing_env_returns_503(client: TestClient) -> None:
    """AEVUM_BREAK_GLASS_TOKEN not set returns 503."""
    env = {k: v for k, v in os.environ.items() if k != "AEVUM_BREAK_GLASS_TOKEN"}
    with patch.dict(os.environ, env, clear=True):
        resp = client.post(
            "/v1/break-glass",
            json=_BG_BODY,
            headers={"X-Break-Glass-Token": _BG_TOKEN},
        )
    assert resp.status_code == 503


def test_break_glass_writes_sigchain_entry(client: TestClient, engine: Engine) -> None:
    """Break-glass invocation records a sigchain entry with break-glass context."""
    with patch.dict(os.environ, {"AEVUM_BREAK_GLASS_TOKEN": _BG_TOKEN}):
        resp = client.post(
            "/v1/break-glass",
            json=_BG_BODY,
            headers={"X-Break-Glass-Token": _BG_TOKEN},
        )
    assert resp.status_code == 200
    audit_id = resp.json()["audit_id"]

    entries = list(engine._ledger.all_events())
    bg_entries = [e for e in entries if e.event_type == "security.break_glass"]
    assert len(bg_entries) == 1
    assert bg_entries[0].payload["break_glass_reason"] == _BG_BODY["reason"]
    assert bg_entries[0].payload["requester"] == _BG_BODY["requester"]
    assert bg_entries[0].audit_id() == audit_id


def test_break_glass_sigchain_entry_has_high_classification(
    client: TestClient, engine: Engine
) -> None:
    """Break-glass sigchain entry records classification=3 (highest sensitivity)."""
    with patch.dict(os.environ, {"AEVUM_BREAK_GLASS_TOKEN": _BG_TOKEN}):
        resp = client.post(
            "/v1/break-glass",
            json=_BG_BODY,
            headers={"X-Break-Glass-Token": _BG_TOKEN},
        )
    assert resp.status_code == 200
    entries = list(engine._ledger.all_events())
    bg_entry = next(e for e in entries if e.event_type == "security.break_glass")
    assert bg_entry.payload["classification"] == 3
