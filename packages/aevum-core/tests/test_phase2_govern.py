# SPDX-License-Identifier: Apache-2.0
"""Phase 2 — GOVERN checkpoint tests."""
import json
from datetime import datetime

import pytest

from aevum.core.cedar_engine import CedarPolicyEngine
from aevum.core.govern import (
    DEFAULT_GOVERN_TIMEOUT_SECONDS,
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
