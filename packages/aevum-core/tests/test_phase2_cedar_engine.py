# SPDX-License-Identifier: Apache-2.0
"""Phase 2 — CedarPolicyEngine and five unconditional barrier tests."""
from pathlib import Path

import pytest

pytest.importorskip("cedarpy", reason="cedarpy not installed — skip Cedar tests")

from aevum.core.cedar_engine import CedarPolicyEngine, PolicyError

# ---------------------------------------------------------------------------
# Engine loading
# ---------------------------------------------------------------------------

class TestCedarPolicyEngineLoad:
    def test_default_loads_policy_files(self):
        engine = CedarPolicyEngine.default()
        assert len(engine.policy_text) > 0

    def test_policy_text_contains_barrier_1(self):
        engine = CedarPolicyEngine.default()
        assert "relate_graph_write" in engine.policy_text

    def test_policy_text_contains_barrier_4(self):
        engine = CedarPolicyEngine.default()
        assert "delete_audit_event" in engine.policy_text

    def test_policy_text_contains_barrier_5(self):
        engine = CedarPolicyEngine.default()
        assert "human_checkpoint_completed" in engine.policy_text

    def test_policy_text_contains_trifecta(self):
        engine = CedarPolicyEngine.default()
        assert "taint_reads_untrusted" in engine.policy_text

    def test_policy_text_contains_all_four_files(self):
        engine = CedarPolicyEngine.default()
        # Each file contributes a distinctive keyword
        assert "relate_graph_write" in engine.policy_text   # barriers
        assert "taint_reads_private" in engine.policy_text  # trifecta
        assert "autonomy_level" in engine.policy_text       # autonomy
        assert "govern_review" in engine.policy_text        # permits

    def test_missing_policy_dir_raises_policy_error(self, monkeypatch):
        import aevum.core.policy.cedar_engine as mod
        monkeypatch.setattr(mod, "_POLICY_DIR", Path("/nonexistent/path/policies"))
        with pytest.raises(PolicyError, match="not found"):
            CedarPolicyEngine.default()

    def test_empty_policy_dir_raises_policy_error(self, tmp_path, monkeypatch):
        import aevum.core.policy.cedar_engine as mod
        monkeypatch.setattr(mod, "_POLICY_DIR", tmp_path)
        with pytest.raises(PolicyError, match="No .cedar files"):
            CedarPolicyEngine.default()

    def test_validate_returns_empty_list_for_valid_policies(self):
        engine = CedarPolicyEngine.default()
        errors = engine.validate()
        assert errors == []

    def test_policy_text_property(self):
        engine = CedarPolicyEngine.default()
        text = engine.policy_text
        assert isinstance(text, str)
        assert len(text) > 500

    def test_custom_policy_text(self):
        policy = 'permit(principal, action, resource);'
        engine = CedarPolicyEngine(policy)
        assert engine.policy_text == policy

    def test_is_permitted_returns_bool(self):
        engine = CedarPolicyEngine.default()
        result = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": False, "has_provenance": True},
        )
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Barrier 1 — Crisis
# ---------------------------------------------------------------------------

class TestBarrier1Crisis:
    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def test_crisis_content_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": True, "has_provenance": True},
        )
        assert not permitted

    def test_no_crisis_content_permitted(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": False, "has_provenance": True},
        )
        assert permitted

    def test_missing_crisis_context_defaults_to_no_crisis(self, engine):
        # No has_crisis_content in context → barrier 1 `when` does not fire
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_provenance": True},
        )
        assert permitted

    def test_crisis_overrides_all_permits(self, engine):
        # Even with all other good context, crisis still blocks
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={
                "has_crisis_content": True,
                "has_active_consent": True,
                "consent_purpose_matches": True,
                "data_classification_level": 0,
                "deployment_ceiling_level": 3,
                "has_provenance": True,
            },
        )
        assert not permitted

    def test_crisis_barrier_different_principal_ids(self, engine):
        for principal_id in ["agent-1", "session-abc", "system"]:
            permitted = engine.is_permitted(
                principal_type="AevumAgent",
                principal_id=principal_id,
                action="relate_graph_write",
                resource_type="DataGraph",
                resource_id="knowledge",
                context={"has_crisis_content": True, "has_provenance": True},
            )
            assert not permitted, f"Barrier 1 failed for principal {principal_id!r}"


# ---------------------------------------------------------------------------
# Barrier 2 — Consent
# ---------------------------------------------------------------------------

class TestBarrier2Consent:
    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def test_no_consent_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_active_consent": False, "consent_purpose_matches": False},
        )
        assert not permitted

    def test_active_consent_with_matching_purpose_permitted(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_active_consent": True, "consent_purpose_matches": True},
        )
        assert permitted

    def test_consent_without_purpose_match_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_active_consent": True, "consent_purpose_matches": False},
        )
        assert not permitted

    def test_purpose_match_without_active_consent_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_active_consent": False, "consent_purpose_matches": True},
        )
        assert not permitted

    def test_missing_consent_context_denied(self, engine):
        # No consent context at all → unless clause not satisfied → forbid fires
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={},
        )
        assert not permitted

    def test_consent_barrier_only_applies_to_navigate(self, engine):
        # relate_graph_write is NOT gated by consent barrier
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": False, "has_provenance": True},  # no consent needed for relate
        )
        assert permitted


# ---------------------------------------------------------------------------
# Barrier 3 — Classification Ceiling
# ---------------------------------------------------------------------------

class TestBarrier3Classification:
    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def test_data_above_ceiling_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={
                "has_active_consent": True, "consent_purpose_matches": True,
                "data_classification_level": 4,   # SECRET
                "deployment_ceiling_level": 2,    # CONFIDENTIAL ceiling
            },
        )
        assert not permitted

    def test_data_at_ceiling_permitted(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={
                "has_active_consent": True, "consent_purpose_matches": True,
                "data_classification_level": 2,
                "deployment_ceiling_level": 2,
            },
        )
        assert permitted

    def test_data_below_ceiling_permitted(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={
                "has_active_consent": True, "consent_purpose_matches": True,
                "data_classification_level": 0,
                "deployment_ceiling_level": 3,
            },
        )
        assert permitted

    def test_phi_above_confidential_ceiling_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={
                "has_active_consent": True, "consent_purpose_matches": True,
                "data_classification_level": 3,   # PHI
                "deployment_ceiling_level": 1,    # INTERNAL ceiling
            },
        )
        assert not permitted

    def test_ceiling_applies_to_all_actions(self, engine):
        # Barrier 3 uses bare `action` (all actions)
        for action in ["navigate", "relate_graph_write", "govern_approve"]:
            permitted = engine.is_permitted(
                principal_type="AevumAgent",
                principal_id="test-agent",
                action=action,
                resource_type="DataGraph",
                resource_id="knowledge",
                context={
                    "data_classification_level": 4,
                    "deployment_ceiling_level": 1,
                    # include consent context for navigate
                    "has_active_consent": True, "consent_purpose_matches": True,
                    "has_crisis_content": False,
                    "action_reversible": True, "action_consequential": False,
                    "human_checkpoint_completed": False,
                    "autonomy_level": 5,
                    "has_provenance": True,
                },
            )
            assert not permitted, f"Ceiling barrier should block {action!r}"


# ---------------------------------------------------------------------------
# Barrier 4 — Audit Seal
# ---------------------------------------------------------------------------

class TestBarrier4AuditSeal:
    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def test_delete_audit_event_always_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="delete_audit_event",
            resource_type="DataGraph",
            resource_id="provenance",
            context={},
        )
        assert not permitted

    def test_update_audit_event_always_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="update_audit_event",
            resource_type="DataGraph",
            resource_id="provenance",
            context={},
        )
        assert not permitted

    def test_truncate_audit_chain_always_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="truncate_audit_chain",
            resource_type="DataGraph",
            resource_id="provenance",
            context={},
        )
        assert not permitted

    def test_rewrite_audit_chain_always_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="rewrite_audit_chain",
            resource_type="DataGraph",
            resource_id="provenance",
            context={},
        )
        assert not permitted

    def test_remember_commit_permitted(self, engine):
        """Appending to the audit chain is permitted — barrier 4 only blocks mutations."""
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="remember_commit",
            resource_type="DataGraph",
            resource_id="provenance",
            context={},
        )
        assert permitted

    def test_audit_seal_is_unconditional(self, engine):
        # Even with a full permissive context, delete is still denied
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="delete_audit_event",
            resource_type="DataGraph",
            resource_id="provenance",
            context={
                "has_active_consent": True, "consent_purpose_matches": True,
                "human_checkpoint_completed": True,
                "data_classification_level": 0, "deployment_ceiling_level": 4,
            },
        )
        assert not permitted


# ---------------------------------------------------------------------------
# Autonomy-L3 — Govern / Human Checkpoint
# (forbid relocated from barriers.cedar to autonomy.cedar in W5)
# ---------------------------------------------------------------------------

class TestAutonomyL3GovernCheckpoint:
    """Autonomy-L3 govern/human-checkpoint forbid (relocated from barriers.cedar in W5).
    Covers the autonomy.cedar rule, not a kernel barrier."""

    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def _ctx(self, reviewed: bool, reversible: bool = False, consequential: bool = True) -> dict:
        return {
            "action_reversible": reversible,
            "action_consequential": consequential,
            "has_crisis_content": False,
            "has_active_consent": True,
            "consent_purpose_matches": True,
            "data_classification_level": 0,
            "deployment_ceiling_level": 3,
            "autonomy_level": 3,
            "human_checkpoint_completed": reviewed,
        }

    def test_irrev_consequential_without_review_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="govern_approve",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=self._ctx(reviewed=False, reversible=False, consequential=True),
        )
        assert not permitted

    def test_irrev_consequential_after_review_permitted(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="govern_approve",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=self._ctx(reviewed=True, reversible=False, consequential=True),
        )
        assert permitted

    def test_reversible_action_permitted_without_review(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="govern_approve",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=self._ctx(reviewed=False, reversible=True, consequential=True),
        )
        assert permitted

    def test_irrev_non_consequential_permitted_without_review(self, engine):
        # Autonomy-L3 requires BOTH irreversible AND consequential
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="govern_approve",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=self._ctx(reviewed=False, reversible=False, consequential=False),
        )
        assert permitted


# ---------------------------------------------------------------------------
# Barrier 5 — Provenance
# ---------------------------------------------------------------------------

class TestBarrier5Provenance:
    """Barrier 5 — Provenance: graph WRITES require provenance (source_id present),
    surfaced to the policy as context.has_provenance. Fail-closed: a write is denied
    unless has_provenance == true. Mirrors the kernel's check_provenance (defense-in-depth)."""

    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def test_write_without_provenance_denied(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": False},  # no has_provenance → fail-closed deny
        )
        assert not permitted

    def test_write_with_provenance_permitted(self, engine):
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="relate_graph_write",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": False, "has_provenance": True},
        )
        assert permitted

    def test_provenance_only_gates_writes(self, engine):
        # navigate (read) is NOT gated by the provenance barrier (it has its own consent gate)
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="test-agent",
            action="navigate",
            resource_type="DataGraph",
            resource_id="knowledge",
            context={"has_crisis_content": False, "has_active_consent": True,
                     "consent_purpose_matches": True},
        )
        assert permitted
