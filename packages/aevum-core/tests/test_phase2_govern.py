# SPDX-License-Identifier: Apache-2.0
"""Phase 2 — GOVERN checkpoint tests."""
import json
from datetime import UTC, datetime

import pytest

from aevum.core.cedar_engine import CedarPolicyEngine
from aevum.core.govern import (
    DEFAULT_GOVERN_TIMEOUT_SECONDS,
    CheckpointResult,
    GovernCheckpoint,
    GovernOutcome,
    ProposedAction,
)


@pytest.fixture
def engine():
    return CedarPolicyEngine.default()


def _irrev_action(**kw):
    defaults = dict(
        action_type="send_email",
        reversible=False,
        consequential=True,
        affects=["user:alice"],
        description="Send billing email",
    )
    defaults.update(kw)
    return ProposedAction(**defaults)


def _rev_action(**kw):
    defaults = dict(
        action_type="update_draft",
        reversible=True,
        consequential=False,
        affects=["draft:123"],
    )
    defaults.update(kw)
    return ProposedAction(**defaults)


# ---------------------------------------------------------------------------
# Veto-as-default
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("cedarpy"),
    reason="cedarpy not installed"
)
class TestGovernCheckpointVetoDefault:
    def test_irrev_consequential_vetoed_without_callback(self, engine):
        gov = GovernCheckpoint(engine, "test-session", review_callback=None)
        result = gov.checkpoint(_irrev_action())
        assert result.vetoed
        assert not result.approved

    def test_irrev_consequential_approved_with_approving_callback(self, engine):
        gov = GovernCheckpoint(engine, "test-session", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        assert result.approved
        assert not result.vetoed

    def test_irrev_consequential_vetoed_with_rejecting_callback(self, engine):
        gov = GovernCheckpoint(engine, "test-session", review_callback=lambda a: False)
        result = gov.checkpoint(_irrev_action())
        assert result.vetoed

    def test_reversible_action_auto_approved_without_callback(self, engine):
        """Reversible actions don't require human review (Barrier 5 doesn't fire)."""
        gov = GovernCheckpoint(engine, "test-session", review_callback=None)
        result = gov.checkpoint(_rev_action())
        assert result.approved

    def test_callback_exception_causes_veto(self, engine):
        def broken(action):
            raise RuntimeError("callback failed")
        gov = GovernCheckpoint(engine, "test-session", review_callback=broken)
        result = gov.checkpoint(_irrev_action())
        assert result.vetoed

    def test_callback_returning_zero_is_veto(self, engine):
        gov = GovernCheckpoint(engine, "test-session", review_callback=lambda a: 0)
        result = gov.checkpoint(_irrev_action())
        assert result.vetoed

    def test_callback_returning_truthy_nonbool_is_approved(self, engine):
        gov = GovernCheckpoint(engine, "test-session", review_callback=lambda a: "yes")
        result = gov.checkpoint(_irrev_action())
        assert result.approved

    def test_non_consequential_action_auto_approved(self, engine):
        action = ProposedAction("log_event", reversible=False, consequential=False, affects=[])
        gov = GovernCheckpoint(engine, "test-session", review_callback=None)
        result = gov.checkpoint(action)
        assert result.approved


# ---------------------------------------------------------------------------
# CheckpointResult fields
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("cedarpy"),
    reason="cedarpy not installed"
)
class TestCheckpointResult:
    @pytest.fixture
    def gov(self, engine):
        return GovernCheckpoint(engine, "my-session", review_callback=None)

    def test_result_has_session_id(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert result.session_id == "my-session"

    def test_result_has_nonempty_checkpoint_id(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert result.checkpoint_id
        assert len(result.checkpoint_id) > 8

    def test_checkpoint_ids_are_unique(self, engine):
        gov = GovernCheckpoint(engine, "sess", review_callback=None)
        r1 = gov.checkpoint(_irrev_action())
        r2 = gov.checkpoint(_irrev_action())
        assert r1.checkpoint_id != r2.checkpoint_id

    def test_result_has_decided_at_timestamp(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert isinstance(result.decided_at, datetime)

    def test_result_has_elapsed_seconds(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert result.elapsed_seconds >= 0.0

    def test_result_has_timeout_seconds(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert result.timeout_seconds == DEFAULT_GOVERN_TIMEOUT_SECONDS

    def test_result_to_dict_is_json_serializable(self, gov):
        result = gov.checkpoint(_irrev_action())
        d = result.to_dict()
        json.dumps(d)  # must not raise

    def test_to_dict_contains_required_keys(self, gov):
        result = gov.checkpoint(_irrev_action())
        d = result.to_dict()
        required = {"action_type", "reversible", "consequential", "affects",
                    "outcome", "decided_at", "decided_by", "session_id",
                    "checkpoint_id", "elapsed_seconds"}
        assert required.issubset(d.keys())

    def test_to_dict_contains_article14_fields(self, gov):
        """EU AI Act Article 14 oversight fields must be present in sigchain record."""
        result = gov.checkpoint(_irrev_action())
        d = result.to_dict()
        article14_fields = {"review_started_at", "review_completed_at",
                            "checklist_acknowledged", "reviewer_id"}
        assert article14_fields.issubset(d.keys())

    def test_to_dict_outcome_is_string(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert isinstance(result.to_dict()["outcome"], str)

    def test_vetoed_decided_by_is_none(self, gov):
        result = gov.checkpoint(_irrev_action())
        assert result.decided_by is None  # veto-as-default, no reviewer

    def test_approved_decided_by_is_set(self, engine):
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        assert result.decided_by is not None
        assert len(result.decided_by) > 0

    def test_proposed_action_preserved_in_result(self, gov):
        action = _irrev_action(action_type="charge_payment", affects=["user:bob"])
        result = gov.checkpoint(action)
        assert result.proposed_action.action_type == "charge_payment"
        assert result.proposed_action.affects == ["user:bob"]


# ---------------------------------------------------------------------------
# CheckpointResult defaults — no cedarpy required
# ---------------------------------------------------------------------------

class TestCheckpointResultDefaults:
    """Article 14 field defaults on CheckpointResult (no engine needed)."""

    def _make_result(self, **overrides: object) -> CheckpointResult:
        now = datetime.now(UTC)
        defaults: dict = dict(
            proposed_action=_irrev_action(),
            outcome=GovernOutcome.VETOED,
            decided_at=now,
            decided_by=None,
            session_id="s",
            checkpoint_id="c",
            timeout_seconds=300.0,
            elapsed_seconds=0.1,
        )
        defaults.update(overrides)
        return CheckpointResult(**defaults)

    def test_article14_fields_default_to_none_or_false(self):
        result = self._make_result()
        assert result.review_started_at is None
        assert result.review_completed_at is None
        assert result.checklist_acknowledged is False
        assert result.reviewer_id is None

    def test_article14_fields_can_be_set(self):
        now = datetime.now(UTC)
        result = self._make_result(
            outcome=GovernOutcome.APPROVED,
            review_started_at=now,
            review_completed_at=now,
            checklist_acknowledged=True,
            reviewer_id="alice",
        )
        assert result.review_started_at == now
        assert result.checklist_acknowledged is True
        assert result.reviewer_id == "alice"

    def test_to_dict_article14_none_fields_serializable(self):
        result = self._make_result()
        d = result.to_dict()
        assert d["review_started_at"] is None
        assert d["review_completed_at"] is None
        assert d["checklist_acknowledged"] is False
        assert d["reviewer_id"] is None
        json.dumps(d)  # must not raise

    def test_to_dict_article14_set_fields_are_iso_strings(self):
        now = datetime.now(UTC)
        result = self._make_result(
            outcome=GovernOutcome.APPROVED,
            review_started_at=now,
            review_completed_at=now,
            checklist_acknowledged=True,
            reviewer_id="bob",
        )
        d = result.to_dict()
        assert isinstance(d["review_started_at"], str)
        assert isinstance(d["review_completed_at"], str)
        datetime.fromisoformat(d["review_started_at"])  # must not raise
        json.dumps(d)  # must not raise


# ---------------------------------------------------------------------------
# EU AI Act Article 14 — human oversight recording (p3-11)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("cedarpy"),
    reason="cedarpy not installed"
)
class TestArticle14OversightFields:
    """p3-11: GOVERN checkpoint records dwell time and acknowledgment for Article 14."""

    def test_auto_approved_has_no_review_timestamps(self, engine):
        """Cedar-automatic-permit: no human was involved, timestamps are None."""
        gov = GovernCheckpoint(engine, "sess", review_callback=None)
        result = gov.checkpoint(_rev_action())  # reversible — auto-approved by Cedar
        assert result.review_started_at is None
        assert result.review_completed_at is None
        assert result.checklist_acknowledged is False
        assert result.reviewer_id is None

    def test_human_approved_has_review_timestamps(self, engine):
        """Human-approved checkpoint records when review started and completed."""
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        assert result.review_started_at is not None
        assert result.review_completed_at is not None
        assert isinstance(result.review_started_at, datetime)
        assert isinstance(result.review_completed_at, datetime)
        assert result.review_completed_at >= result.review_started_at

    def test_human_approved_sets_checklist_acknowledged(self, engine):
        """Human approval implies checklist acknowledgment."""
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        assert result.checklist_acknowledged is True
        assert result.reviewer_id is not None

    def test_veto_as_default_has_no_checklist_acknowledgment(self, engine):
        """No callback: veto-as-default, no human acknowledgment recorded."""
        gov = GovernCheckpoint(engine, "sess", review_callback=None)
        result = gov.checkpoint(_irrev_action())
        assert result.checklist_acknowledged is False
        assert result.reviewer_id is None

    def test_human_vetoed_has_review_timestamps_no_acknowledgment(self, engine):
        """Human explicitly vetoed: timestamps recorded, checklist_acknowledged=False."""
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: False)
        result = gov.checkpoint(_irrev_action())
        assert result.review_started_at is not None
        assert result.checklist_acknowledged is False
        assert result.reviewer_id is None

    def test_article14_fields_in_to_dict(self, engine):
        """All Article 14 fields appear in the sigchain dict (even when None)."""
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        d = result.to_dict()
        assert "review_started_at" in d
        assert "review_completed_at" in d
        assert "checklist_acknowledged" in d
        assert "reviewer_id" in d

    def test_article14_timestamps_are_iso_strings_in_to_dict(self, engine):
        """Timestamps are ISO-format strings (or None) in sigchain dict."""
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        d = result.to_dict()
        assert isinstance(d["review_started_at"], str)
        assert isinstance(d["review_completed_at"], str)
        # Validate ISO format — must not raise
        datetime.fromisoformat(d["review_started_at"])
        datetime.fromisoformat(d["review_completed_at"])

    def test_to_dict_is_json_serializable_with_article14_fields(self, engine):
        """Full sigchain record including Article 14 fields must be JSON-serializable."""
        gov = GovernCheckpoint(engine, "sess", review_callback=lambda a: True)
        result = gov.checkpoint(_irrev_action())
        json.dumps(result.to_dict())  # must not raise


# ---------------------------------------------------------------------------
# GovernOutcome enum
# ---------------------------------------------------------------------------

class TestGovernOutcomeEnum:
    def test_approved_value(self):
        assert GovernOutcome.APPROVED.value == "approved"

    def test_vetoed_value(self):
        assert GovernOutcome.VETOED.value == "vetoed"

    def test_crisis_value(self):
        assert GovernOutcome.CRISIS.value == "crisis"

    def test_outcome_is_str_subclass(self):
        assert isinstance(GovernOutcome.APPROVED, str)


# ---------------------------------------------------------------------------
# ProposedAction dataclass
# ---------------------------------------------------------------------------

class TestProposedAction:
    def test_frozen(self):
        import dataclasses
        action = _irrev_action()
        with pytest.raises(dataclasses.FrozenInstanceError):
            action.action_type = "mutated"  # type: ignore[misc]

    def test_default_classification(self):
        action = _irrev_action()
        assert action.classification == "UNCLASSIFIED"

    def test_custom_classification(self):
        action = ProposedAction("op", False, True, [], classification="PHI")
        assert action.classification == "PHI"

    def test_metadata_defaults_to_empty_dict(self):
        action = _irrev_action()
        assert action.metadata == {}

    def test_description_defaults_to_empty_string(self):
        action = ProposedAction("op", False, True, [])
        assert action.description == ""


# ---------------------------------------------------------------------------
# Classification level conversion
# ---------------------------------------------------------------------------

class TestClassificationLevel:
    def test_known_levels(self):
        from aevum.core.govern import GovernCheckpoint
        fn = GovernCheckpoint._classification_level
        assert fn("UNCLASSIFIED") == 0
        assert fn("INTERNAL") == 1
        assert fn("CONFIDENTIAL") == 2
        assert fn("PHI") == 3
        assert fn("SECRET") == 4

    def test_unknown_defaults_to_zero(self):
        from aevum.core.govern import GovernCheckpoint
        assert GovernCheckpoint._classification_level("UNKNOWN") == 0
        assert GovernCheckpoint._classification_level("") == 0

    def test_case_insensitive(self):
        from aevum.core.govern import GovernCheckpoint
        assert GovernCheckpoint._classification_level("phi") == 3
        assert GovernCheckpoint._classification_level("Secret") == 4
