"""
Tests for PublishComplication.
Uses mocked httpx and Engine — no real Rekor instance required.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import unittest.mock

import pytest


def _make_mock_engine(entries: list[dict] | None = None) -> unittest.mock.MagicMock:
    """Minimal engine mock with configurable ledger entries."""
    engine = unittest.mock.MagicMock()
    engine.get_ledger_entries.return_value = entries or [
        {
            "sequence": 3,
            "prior_hash": "a" * 64,
            "signer_key_id": "test-key-id",
            "system_time": 1746000000000000000,
            "event_type": "session.start",
            "actor": "aevum-core",
        }
    ]
    engine._ledger.append = unittest.mock.MagicMock(return_value=None)
    return engine


def _make_mock_rekor_response(
    log_index: int = 42, uuid: str = "abc123def456"
) -> unittest.mock.MagicMock:
    """Mock a successful Rekor submission response."""
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 201
    mock_resp.raise_for_status = unittest.mock.MagicMock(return_value=None)
    mock_resp.json.return_value = {uuid: {"logIndex": log_index, "body": "..."}}
    return mock_resp


class TestPublishComplicationCheckpoint:

    def test_on_approved_submits_initial_checkpoint(self) -> None:
        """Approval must trigger an immediate initial checkpoint."""
        from aevum.publish import PublishComplication

        mock_engine = _make_mock_engine()
        comp = PublishComplication(rekor_url="https://mock.rekor.test")
        mock_resp = _make_mock_rekor_response(log_index=1, uuid="uuid-0001")

        with unittest.mock.patch("httpx.post", return_value=mock_resp) as mock_post:
            comp.on_approved(mock_engine)

        mock_post.assert_called_once()
        mock_engine._ledger.append.assert_called_once()
        call_kwargs = mock_engine._ledger.append.call_args.kwargs
        assert call_kwargs["event_type"] == "transparency.checkpoint"
        assert call_kwargs["actor"] == "aevum-publish"
        payload = call_kwargs["payload"]
        assert payload["rekor_log_index"] == 1
        assert payload["rekor_entry_hash"] == "uuid-0001"
        assert payload["rekor_server"] == "https://mock.rekor.test"

    def test_n_events_threshold_triggers_checkpoint(self) -> None:
        """After N events, on_event_written must submit a checkpoint."""
        from aevum.publish import PublishComplication

        mock_engine = _make_mock_engine()
        comp = PublishComplication(
            rekor_url="https://mock.rekor.test",
            every_n_events=3,
            every_seconds=9999,
        )
        mock_resp = _make_mock_rekor_response()

        with unittest.mock.patch("httpx.post", return_value=mock_resp) as mock_post:
            comp.on_approved(mock_engine)     # initial checkpoint (call 1)
            mock_post.reset_mock()
            mock_engine._ledger.append.reset_mock()

            comp.on_event_written()           # 1 of 3
            comp.on_event_written()           # 2 of 3
            assert not mock_post.called       # not yet

            comp.on_event_written()           # 3 of 3 — threshold reached

        mock_post.assert_called_once()
        mock_engine._ledger.append.assert_called_once()
        payload = mock_engine._ledger.append.call_args.kwargs["payload"]
        assert payload["checkpoint_reason"] == "n_events"

    def test_time_threshold_triggers_checkpoint(self) -> None:
        """After every_seconds, on_event_written must submit a checkpoint."""
        from aevum.publish import PublishComplication

        mock_engine = _make_mock_engine()
        comp = PublishComplication(
            rekor_url="https://mock.rekor.test",
            every_n_events=9999,
            every_seconds=1,
        )
        mock_resp = _make_mock_rekor_response()

        with unittest.mock.patch("httpx.post", return_value=mock_resp) as mock_post:
            comp.on_approved(mock_engine)
            mock_post.reset_mock()
            mock_engine._ledger.append.reset_mock()

            comp._last_checkpoint_time = time.monotonic() - 2.0
            comp.on_event_written()

        mock_post.assert_called_once()
        payload = mock_engine._ledger.append.call_args.kwargs["payload"]
        assert payload["checkpoint_reason"] == "interval"

    def test_rekor_failure_does_not_raise(self) -> None:
        """Rekor submission failure must warn and not raise."""
        from aevum.publish import PublishComplication

        mock_engine = _make_mock_engine()
        comp = PublishComplication(
            rekor_url="https://mock.rekor.test",
            every_n_events=1,
            every_seconds=9999,
        )

        import httpx

        with unittest.mock.patch(
            "httpx.post", side_effect=httpx.ConnectError("Connection refused")
        ):
            comp.on_approved(mock_engine)
            comp.on_event_written()

        assert mock_engine._ledger.append.call_count == 0

    def test_httpx_missing_degrades_gracefully(self) -> None:
        """Missing httpx must warn and not raise."""
        from aevum.publish import PublishComplication

        mock_engine = _make_mock_engine()
        comp = PublishComplication()

        with unittest.mock.patch.dict(sys.modules, {"httpx": None}):
            comp.on_approved(mock_engine)

        mock_engine._ledger.append.assert_not_called()

    def test_checkpoint_digest_is_deterministic(self) -> None:
        """Same inputs must always produce same digest."""
        from aevum.publish.complication import _compute_checkpoint_digest

        d1 = _compute_checkpoint_digest(42, "a" * 64, "key-id", 1746000000)
        d2 = _compute_checkpoint_digest(42, "a" * 64, "key-id", 1746000000)
        assert d1 == d2
        assert len(d1) == 32  # SHA-256 = 32 bytes

    def test_checkpoint_digest_uses_sha256_not_sha3(self) -> None:
        """Rekor expects SHA-256; chain internal integrity uses SHA3-256."""
        from aevum.publish.complication import _compute_checkpoint_digest

        digest = _compute_checkpoint_digest(1, "0" * 64, "k", 0)
        record = json.dumps(
            {
                "sequence": 1,
                "prior_hash": "0" * 64,
                "signer_key_id": "k",
                "system_time": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        expected = hashlib.sha256(record).digest()
        assert digest == expected

    def test_rekor_url_trailing_slash_stripped(self) -> None:
        """Trailing slash in rekor_url must not double-slash the endpoint."""
        from aevum.publish import PublishComplication

        comp = PublishComplication(rekor_url="https://rekor.example.com/")
        assert not comp._rekor_url.endswith("/")


class TestPublishComplicationIntegration:

    def test_transparency_checkpoint_in_sigchain(self) -> None:
        """transparency.checkpoint must be a verifiable, signed chain entry."""
        # Phase 0 finding: Engine does not call on_approved automatically.
        # Callers must invoke comp.on_approved(engine) explicitly after
        # engine.approve_complication("aevum-publish"). Same pattern as aevum-spiffe.
        sys.path.insert(0, "packages/aevum-core/src")
        from aevum.core import Engine
        from aevum.publish import PublishComplication

        mock_resp = _make_mock_rekor_response(log_index=99, uuid="test-uuid-publish")

        comp = PublishComplication(
            rekor_url="https://mock.rekor.test",
            every_n_events=9999,
            every_seconds=9999,
        )

        engine = Engine()

        with unittest.mock.patch("httpx.post", return_value=mock_resp):
            engine.install_complication(comp)
            engine.approve_complication("aevum-publish")
            comp.on_approved(engine)  # must be called explicitly per aevum-spiffe pattern

        entries = engine.get_ledger_entries()
        event_types = [e["event_type"] for e in entries]

        assert "transparency.checkpoint" in event_types, (
            f"transparency.checkpoint not in chain. Events: {event_types}"
        )
        assert engine.verify_sigchain() is True

        cp = next(e for e in entries if e["event_type"] == "transparency.checkpoint")
        assert cp["payload"]["rekor_log_index"] == 99
        assert cp["payload"]["rekor_server"] == "https://mock.rekor.test"
        assert cp["actor"] == "aevum-publish"
