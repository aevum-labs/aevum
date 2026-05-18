# SPDX-License-Identifier: Apache-2.0
"""
Structured HITL tests — verify that the consent gate requires explicit typed
acknowledgment, records dwell time, and surfaces automation bias warnings.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aevum.core.engine import Engine
    from fastapi.testclient import TestClient

_ACTION_DESC = "Deploy security patch to production"


def _create_review(client: TestClient, description: str = _ACTION_DESC) -> str:
    """Helper: create a pending review and return review_id."""
    resp = client.post("/v1/consent/review", json={"action_description": description})
    assert resp.status_code == 200, resp.text
    return resp.json()["review_id"]


def _approval_body(review_id: str) -> dict:
    return {
        "review_id": review_id,
        "acknowledged_intent": "Applying CVE-2026-1234 patch to dependency X",
        "acknowledged_blast_radius": "Could break API clients using deprecated field",
        "acknowledged_rollback": "git revert + redeploy takes under 5 minutes",
        "reviewer_id": "neo",
    }


def test_approval_requires_all_fields(client: TestClient) -> None:
    """Approval without structured fields is rejected 422."""
    resp = client.post("/v1/consent/approve", json={"reviewer_id": "neo"})
    assert resp.status_code == 422


def test_approval_requires_min_length(client: TestClient) -> None:
    """Fields shorter than 10 characters are rejected 422."""
    review_id = _create_review(client)
    resp = client.post("/v1/consent/approve", json={
        "review_id": review_id,
        "acknowledged_intent": "short",          # < 10 chars
        "acknowledged_blast_radius": "Could break API clients using deprecated field",
        "acknowledged_rollback": "git revert + redeploy",
        "reviewer_id": "neo",
    })
    assert resp.status_code == 422


def test_approval_records_dwell_time(client: TestClient, engine: Engine) -> None:
    """Dwell time is present and positive in the sigchain entry."""
    review_id = _create_review(client)
    time.sleep(0.05)  # ensure non-zero elapsed time
    resp = client.post("/v1/consent/approve", json=_approval_body(review_id))
    assert resp.status_code == 200, resp.text
    assert resp.json()["dwell_time_seconds"] > 0

    entries = [e for e in engine._ledger.all_events() if e.event_type == "consent.approved"]
    assert len(entries) == 1
    assert entries[0].payload["dwell_time_seconds"] > 0
    assert entries[0].payload["reviewer_id"] == "neo"


def test_fast_approval_sets_warning_flag(client: TestClient, engine: Engine) -> None:
    """Approvals under 30s set automation_bias_warning=True."""
    review_id = _create_review(client)
    # Approve immediately — well under 30s threshold
    resp = client.post("/v1/consent/approve", json=_approval_body(review_id))
    assert resp.status_code == 200, resp.text
    assert resp.json()["automation_bias_warning"] is True

    entries = [e for e in engine._ledger.all_events() if e.event_type == "consent.approved"]
    assert entries[-1].payload["automation_bias_warning"] is True


def test_approval_not_found_for_unknown_review(client: TestClient) -> None:
    """Approving an unknown review_id returns 404."""
    resp = client.post("/v1/consent/approve", json=_approval_body("nonexistent-review-id"))
    assert resp.status_code == 404


def test_review_records_sigchain_entry(client: TestClient, engine: Engine) -> None:
    """Creating a review records a consent.review_requested entry in the sigchain."""
    client.post(
        "/v1/consent/review",
        json={"action_description": _ACTION_DESC},
    )
    entries = [
        e for e in engine._ledger.all_events()
        if e.event_type == "consent.review_requested"
    ]
    assert len(entries) == 1
    assert "review_id" in entries[0].payload


def test_approval_consumed_once(client: TestClient) -> None:
    """A review_id can only be approved once — second attempt returns 404."""
    review_id = _create_review(client)
    resp1 = client.post("/v1/consent/approve", json=_approval_body(review_id))
    assert resp1.status_code == 200
    resp2 = client.post("/v1/consent/approve", json=_approval_body(review_id))
    assert resp2.status_code == 404
