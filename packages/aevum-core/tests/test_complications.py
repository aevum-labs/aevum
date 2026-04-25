"""
Tests for complication framework: registry, circuit breaker,
manifest validation, conflict detection, webhook dispatch.

NO tests/__init__.py — direct imports via pythonpath = ["src", "tests"].
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from aevum.core.complications.circuit_breaker import CBState, CircuitBreaker
from aevum.core.complications.conflict import ConflictDetector
from aevum.core.complications.manifest_validator import ManifestValidator
from aevum.core.complications.registry import ComplicationRegistry, ComplicationState
from aevum.core.complications.webhook import WebhookRegistry
from aevum.core.exceptions import ComplicationError

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_manifest(name: str = "test-comp", caps: list[str] | None = None) -> dict:
    return {
        "name": name,
        "version": "0.1.0",
        "description": f"Test complication {name}",
        "capabilities": caps or [name],
        "classification_max": 0,
        "functions": ["query"],
        "auth": {"scopes_required": [], "public_key": None},
        "schema_version": "1.0",
    }


class _FakeComp:
    """Minimal complication instance for registry tests."""
    def __init__(self, name: str = "test-comp", caps: list[str] | None = None) -> None:
        self.name = name
        self.version = "0.1.0"
        self.capabilities = caps or [name]

    def manifest(self) -> dict:
        return _make_manifest(self.name, self.capabilities)

    def health(self) -> bool:
        return True

    async def run(self, ctx: dict, payload: dict) -> dict:
        return {"result": f"from {self.name}"}


# ── Registry state machine ────────────────────────────────────────────────────

class TestRegistry:
    def test_install_starts_in_discovered(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        assert reg.state("test-comp") == ComplicationState.DISCOVERED

    def test_full_lifecycle(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        assert reg.state("test-comp") == ComplicationState.DISCOVERED
        reg.validate("test-comp")
        assert reg.state("test-comp") == ComplicationState.PENDING
        reg.approve("test-comp")
        assert reg.state("test-comp") == ComplicationState.ACTIVE
        reg.suspend("test-comp")
        assert reg.state("test-comp") == ComplicationState.SUSPENDED
        reg.resume("test-comp")
        assert reg.state("test-comp") == ComplicationState.ACTIVE
        reg.decommission("test-comp")
        assert reg.state("test-comp") == ComplicationState.DECOMMISSIONED

    def test_reject_from_pending(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        reg.validate("test-comp")
        reg.reject("test-comp")
        assert reg.state("test-comp") == ComplicationState.REJECTED

    def test_invalid_transition_raises(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        with pytest.raises(ComplicationError, match="Invalid transition"):
            reg.approve("test-comp")  # Can't go DISCOVERED → APPROVED

    def test_decommissioned_terminal(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        reg.validate("test-comp")
        reg.approve("test-comp")
        reg.decommission("test-comp")
        with pytest.raises(ComplicationError, match="terminal"):
            reg.resume("test-comp")

    def test_active_complications_only_returns_active(self) -> None:
        reg = ComplicationRegistry()
        for name in ["a", "b", "c"]:
            comp = _FakeComp(name)
            reg.install(comp.manifest(), comp)
            reg.validate(name)
            reg.approve(name)
        reg.suspend("b")
        active = [c.name for c in reg.active_complications()]
        assert "a" in active
        assert "c" in active
        assert "b" not in active

    def test_reinstall_after_decommission(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        reg.validate("test-comp")
        reg.approve("test-comp")
        reg.decommission("test-comp")
        # Should be installable again
        reg.install(comp.manifest(), comp)
        assert reg.state("test-comp") == ComplicationState.DISCOVERED

    def test_duplicate_install_raises(self) -> None:
        reg = ComplicationRegistry()
        comp = _FakeComp()
        reg.install(comp.manifest(), comp)
        reg.validate("test-comp")
        reg.approve("test-comp")
        with pytest.raises(ComplicationError, match="already exists"):
            reg.install(comp.manifest(), comp)

    def test_not_found_raises(self) -> None:
        reg = ComplicationRegistry()
        with pytest.raises(ComplicationError, match="not found"):
            reg.state("nonexistent")


# ── Circuit breaker ───────────────────────────────────────────────────────────

class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        cb = CircuitBreaker()
        assert cb.state == CBState.CLOSED
        assert cb.allow_request() is True

    def test_trips_after_threshold(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CBState.OPEN
        assert cb.allow_request() is False

    def test_success_resets_counter(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()  # Counter reset — only 1 failure now
        assert cb.state == CBState.CLOSED

    def test_recovery_to_half_open(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, recovery_seconds=0.05)
        cb.record_failure()
        assert cb.state == CBState.OPEN
        time.sleep(0.1)
        assert cb.state == CBState.HALF_OPEN
        assert cb.allow_request() is True

    def test_manual_reset(self) -> None:
        cb = CircuitBreaker(failure_threshold=1)
        cb.record_failure()
        assert cb.state == CBState.OPEN
        cb.reset()
        assert cb.state == CBState.CLOSED
        assert cb.allow_request() is True


# ── Manifest validator ────────────────────────────────────────────────────────

class TestManifestValidator:
    def _valid(self, **overrides: object) -> dict:
        m = _make_manifest()
        m.update(overrides)
        return m

    def test_valid_manifest_no_errors(self) -> None:
        v = ManifestValidator()
        assert v.validate(_make_manifest()) == []

    def test_missing_name_fails(self) -> None:
        v = ManifestValidator()
        m = _make_manifest()
        del m["name"]
        assert any("name" in e for e in v.validate(m))

    def test_empty_capabilities_fails(self) -> None:
        v = ManifestValidator()
        m = _make_manifest()
        m["capabilities"] = []
        assert any("capabilities" in e for e in v.validate(m))

    def test_invalid_classification_fails(self) -> None:
        v = ManifestValidator()
        m = _make_manifest()
        m["classification_max"] = 5
        assert any("classification_max" in e for e in v.validate(m))

    def test_invalid_function_fails(self) -> None:
        v = ManifestValidator()
        m = _make_manifest()
        m["functions"] = ["not-a-function"]
        assert any("functions" in e for e in v.validate(m))

    def test_none_public_key_warns_not_fails(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging
        v = ManifestValidator()
        with caplog.at_level(logging.WARNING):
            errors = v.validate(_make_manifest())
        assert errors == []
        assert "public_key" in caplog.text or "signature" in caplog.text.lower()


# ── Conflict detector ─────────────────────────────────────────────────────────

class TestConflictDetector:
    def test_no_conflict(self) -> None:
        d = ConflictDetector()
        new = _make_manifest("new", ["capability-x"])
        existing = [_make_manifest("old", ["capability-y"])]
        assert d.check(new, existing) == []

    def test_conflict_detected(self) -> None:
        d = ConflictDetector()
        new = _make_manifest("new", ["shared-cap"])
        existing = [_make_manifest("old", ["shared-cap"])]
        conflicts = d.check(new, existing)
        assert len(conflicts) == 1
        assert "shared-cap" in conflicts[0]
        assert "old" in conflicts[0]

    def test_no_conflict_with_empty_registry(self) -> None:
        d = ConflictDetector()
        assert d.check(_make_manifest(), []) == []

    def test_multiple_conflicts_reported(self) -> None:
        d = ConflictDetector()
        new = _make_manifest("new", ["cap-a", "cap-b", "cap-c"])
        existing = [
            _make_manifest("old-1", ["cap-a"]),
            _make_manifest("old-2", ["cap-b"]),
        ]
        conflicts = d.check(new, existing)
        assert len(conflicts) == 2


# ── Webhook registry ──────────────────────────────────────────────────────────

class TestWebhookRegistry:
    def test_register_and_list(self) -> None:
        wr = WebhookRegistry()
        wr.register("w1", "https://example.com/hook", "secret")
        regs = wr.all_registrations()
        assert len(regs) == 1
        assert regs[0]["webhook_id"] == "w1"

    def test_deregister(self) -> None:
        wr = WebhookRegistry()
        wr.register("w1", "https://example.com/hook", "secret")
        wr.deregister("w1")
        assert wr.all_registrations() == []

    def test_dispatch_calls_http_client(self) -> None:
        mock_client = MagicMock()
        wr = WebhookRegistry(http_client=mock_client)
        wr.register("w1", "https://example.com/hook", "secret",
                    events=["review.approved"])
        dispatched = wr.dispatch("review.approved", {"audit_id": "urn:aevum:audit:abc"})
        assert "w1" in dispatched
        assert mock_client.post.called

    def test_dispatch_to_unsubscribed_event_skipped(self) -> None:
        mock_client = MagicMock()
        wr = WebhookRegistry(http_client=mock_client)
        wr.register("w1", "https://example.com/hook", "secret",
                    events=["review.approved"])
        dispatched = wr.dispatch("review.vetoed", {"audit_id": "urn:aevum:audit:abc"})
        assert dispatched == []
        assert not mock_client.post.called

    def test_dispatch_no_http_client_no_error(self) -> None:
        wr = WebhookRegistry()  # no http_client
        wr.register("w1", "https://example.com/hook", "secret")
        # Should not raise — just logs
        dispatched = wr.dispatch("review.approved", {})
        assert "w1" in dispatched

    def test_invalid_url_raises(self) -> None:
        wr = WebhookRegistry()
        with pytest.raises(ValueError, match="HTTPS"):
            wr.register("w1", "http://example.com/hook", "secret")

    def test_localhost_url_allowed(self) -> None:
        wr = WebhookRegistry()
        wr.register("w1", "http://localhost:8080/hook", "secret")
        assert len(wr.all_registrations()) == 1

    def test_hmac_signature_format(self) -> None:
        sig = WebhookRegistry._sign("my-secret", "body-content")
        assert sig.startswith("sha256=")
        assert len(sig) > 7
