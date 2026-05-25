# SPDX-License-Identifier: Apache-2.0
"""Tests for GatekeeperFilter — de-identification for FOQA telemetry export."""

from __future__ import annotations

import secrets

import pytest
from aevum.core.exceedance import EXCEEDANCE_CATALOGUE, ExceedanceEvent

from aevum.otel.gatekeeper import GatekeeperFilter


def _key() -> bytes:
    return secrets.token_bytes(32)


def _filter(key: bytes | None = None) -> GatekeeperFilter:
    return GatekeeperFilter(gatekeeper_key=key or _key())


def _event(**kwargs) -> ExceedanceEvent:
    defaults = dict(
        exceedance_id="EX-03",
        exceedance_name=EXCEEDANCE_CATALOGUE["EX-03"]["name"],
        aviation_analogy=EXCEEDANCE_CATALOGUE["EX-03"]["aviation"],
        session_id="session-real-abc-123",
        agent_id="agent-real-xyz-456",
        detected_at="2026-05-25T00:00:00+00:00",
        receipt_hash="d" * 64,
        severity="CRITICAL",
        details={},
    )
    defaults.update(kwargs)
    return ExceedanceEvent(**defaults)


# ── Key requirement ───────────────────────────────────────────────────────────

class TestKeyRequirement:
    def test_raises_without_key_or_env(self, monkeypatch):
        monkeypatch.delenv("AEVUM_GATEKEEPER_KEY_HEX", raising=False)
        with pytest.raises(RuntimeError, match="AEVUM_GATEKEEPER_KEY_HEX"):
            GatekeeperFilter()

    def test_loads_key_from_env(self, monkeypatch):
        key = secrets.token_bytes(32)
        monkeypatch.setenv("AEVUM_GATEKEEPER_KEY_HEX", key.hex())
        gf = GatekeeperFilter()
        assert gf is not None

    def test_raises_for_short_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            GatekeeperFilter(gatekeeper_key=b"tooshort")

    def test_accepts_exactly_32_bytes(self):
        gf = GatekeeperFilter(gatekeeper_key=b"a" * 32)
        assert gf is not None

    def test_accepts_longer_key(self):
        gf = GatekeeperFilter(gatekeeper_key=b"a" * 64)
        assert gf is not None

    def test_error_message_contains_generate_command(self, monkeypatch):
        monkeypatch.delenv("AEVUM_GATEKEEPER_KEY_HEX", raising=False)
        with pytest.raises(RuntimeError) as exc_info:
            GatekeeperFilter()
        assert "secrets.token_hex" in str(exc_info.value)


# ── Pseudonymization ──────────────────────────────────────────────────────────

class TestPseudonymization:
    def test_deterministic_same_input(self):
        gf = _filter()
        p1 = gf.pseudonymize("session-abc-123")
        p2 = gf.pseudonymize("session-abc-123")
        assert p1 == p2

    def test_prefix_anon(self):
        gf = _filter()
        p = gf.pseudonymize("session-abc-123")
        assert p.startswith("anon-")

    def test_original_not_leaked(self):
        gf = _filter()
        identifier = "session-abc-123"
        p = gf.pseudonymize(identifier)
        assert identifier not in p

    def test_different_inputs_different_pseudonyms(self):
        gf = _filter()
        p1 = gf.pseudonymize("session-001")
        p2 = gf.pseudonymize("session-002")
        assert p1 != p2

    def test_different_keys_different_pseudonyms(self):
        gf1 = GatekeeperFilter(gatekeeper_key=b"k" * 32)
        gf2 = GatekeeperFilter(gatekeeper_key=b"m" * 32)
        p1 = gf1.pseudonymize("same-session")
        p2 = gf2.pseudonymize("same-session")
        assert p1 != p2

    def test_pseudonym_length_fixed(self):
        gf = _filter()
        for identifier in ["a", "b" * 1000, "session-xyz"]:
            p = gf.pseudonymize(identifier)
            # "anon-" + 16 hex chars = 21 chars
            assert len(p) == 21

    def test_empty_string_pseudonymized(self):
        gf = _filter()
        p = gf.pseudonymize("")
        assert p.startswith("anon-")


# ── filter_exceedance ─────────────────────────────────────────────────────────

class TestFilterExceedance:
    def test_session_id_replaced(self):
        gf = _filter()
        ev = _event(session_id="real-session-id")
        filtered = gf.filter_exceedance(ev)
        assert filtered.session_id != "real-session-id"
        assert filtered.session_id.startswith("anon-")

    def test_agent_id_replaced(self):
        gf = _filter()
        ev = _event(agent_id="real-agent-id")
        filtered = gf.filter_exceedance(ev)
        assert filtered.agent_id != "real-agent-id"
        assert filtered.agent_id.startswith("anon-")

    def test_empty_agent_id_stays_empty(self):
        gf = _filter()
        ev = _event(agent_id="")
        filtered = gf.filter_exceedance(ev)
        assert filtered.agent_id == ""

    def test_receipt_hash_truncated(self):
        gf = _filter()
        ev = _event(receipt_hash="d" * 64)
        filtered = gf.filter_exceedance(ev)
        assert filtered.receipt_hash.endswith("...")
        assert len(filtered.receipt_hash) < 64

    def test_exceedance_id_preserved(self):
        gf = _filter()
        ev = _event(exceedance_id="EX-03")
        filtered = gf.filter_exceedance(ev)
        assert filtered.exceedance_id == "EX-03"

    def test_severity_preserved(self):
        gf = _filter()
        ev = _event(severity="CRITICAL")
        filtered = gf.filter_exceedance(ev)
        assert filtered.severity == "CRITICAL"

    def test_pii_stripped_from_details(self):
        gf = _filter()
        ev = _event(details={
            "retry_count": 5,
            "prompt_text": "secret prompt",
            "user_email": "user@example.com",
        })
        filtered = gf.filter_exceedance(ev)
        assert "prompt_text" not in filtered.details
        assert "user_email" not in filtered.details
        assert filtered.details.get("retry_count") == 5

    def test_original_event_not_mutated(self):
        gf = _filter()
        ev = _event(session_id="original-session")
        _ = gf.filter_exceedance(ev)
        assert ev.session_id == "original-session"


# ── filter_attributes ─────────────────────────────────────────────────────────

class TestFilterAttributes:
    def test_strips_prompt_text(self):
        gf = _filter()
        attrs = {"prompt_text": "secret", "aevum.sequence": 42}
        filtered = gf.filter_attributes(attrs)
        assert "prompt_text" not in filtered
        assert filtered.get("aevum.sequence") == 42

    def test_strips_user_containing_keys(self):
        gf = _filter()
        attrs = {"user_id": "123", "user_name": "Alice", "some_user_field": "val"}
        filtered = gf.filter_attributes(attrs)
        for key in attrs:
            assert key not in filtered

    def test_preserves_safe_attrs(self):
        gf = _filter()
        attrs = {
            "exceedance_id": "EX-01",
            "severity": "MEDIUM",
            "aevum.sequence": 10,
        }
        filtered = gf.filter_attributes(attrs)
        assert filtered == attrs

    def test_does_not_mutate_input(self):
        gf = _filter()
        attrs = {"prompt_text": "secret", "safe": "value"}
        original = dict(attrs)
        gf.filter_attributes(attrs)
        assert attrs == original
