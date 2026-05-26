# SPDX-License-Identifier: Apache-2.0
"""
Tests for WebhookRegistry exponential backoff retry and dead-letter behaviour.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.complications.webhook import _RETRY_DELAYS, WebhookRegistry


def _registry_with_mock() -> tuple[WebhookRegistry, MagicMock]:
    mock_client = MagicMock()
    wr = WebhookRegistry(http_client=mock_client)
    wr.register("w1", "https://example.com/hook", "secret",
                events=["review.approved"])
    return wr, mock_client


def _registry_with_ledger() -> tuple[WebhookRegistry, InMemoryLedger, MagicMock]:
    sigchain = Sigchain()
    ledger = InMemoryLedger(sigchain)
    mock_client = MagicMock()
    wr = WebhookRegistry(http_client=mock_client, ledger=ledger)
    wr.register("w1", "https://example.com/hook", "secret",
                events=["review.approved"])
    return wr, ledger, mock_client


class TestWebhookRetry:
    def test_success_on_first_try(self) -> None:
        wr, mock_client = _registry_with_mock()
        dispatched = wr.dispatch("review.approved", {"audit_id": "abc"})
        assert "w1" in dispatched
        assert mock_client.post.call_count == 1

    def test_retry_on_transient_failure(self) -> None:
        wr, mock_client = _registry_with_mock()
        # Fail once then succeed
        mock_client.post.side_effect = [Exception("timeout"), None]
        with patch("time.sleep"):  # Don't actually sleep in tests
            dispatched = wr.dispatch("review.approved", {"audit_id": "abc"})
        assert "w1" in dispatched
        assert mock_client.post.call_count == 2

    def test_dead_letter_on_all_failures(self) -> None:
        wr, ledger, mock_client = _registry_with_ledger()
        mock_client.post.side_effect = Exception("always fails")
        with patch("time.sleep"):
            dispatched = wr.dispatch("review.approved", {"audit_id": "abc"})
        assert "w1" not in dispatched
        # Dead-letter event in ledger
        entries = ledger.all_events()
        dead_letters = [e for e in entries if e.event_type == "barrier.webhook_failed"]
        assert len(dead_letters) == 1
        assert dead_letters[0].payload["webhook_id"] == "w1"

    def test_retry_count_matches_schedule(self) -> None:
        wr, mock_client = _registry_with_mock()
        mock_client.post.side_effect = Exception("always fails")
        with patch("time.sleep"):
            wr.dispatch("review.approved", {})
        assert mock_client.post.call_count == len(_RETRY_DELAYS)

    def test_no_dead_letter_without_ledger(self) -> None:
        """If no ledger configured, dead-letter silently skipped (no crash)."""
        mock_client = MagicMock()
        mock_client.post.side_effect = Exception("fail")
        wr = WebhookRegistry(http_client=mock_client)
        wr.register("w1", "https://example.com/hook", "secret")
        with patch("time.sleep"):
            wr.dispatch("review.approved", {})
        # No exception raised

