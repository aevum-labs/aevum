# SPDX-License-Identifier: Apache-2.0
import dataclasses
import pytest
from datetime import UTC, datetime
from aevum.core.types import (
    ContextBundle, TypedFact, WeightedEdge, ExclusionNote,
    Completeness, SourceType, TaintLabel,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _minimal_bundle(**overrides) -> ContextBundle:
    defaults = dict(
        facts=(),
        edges=(),
        uncertainty=0.5,
        reasoning_trace=("reason",),
        completeness=Completeness.COMPLETE,
        excluded=(),
        consent_ref="test-ref",
        purpose="test",
        assembled_at=_now(),
        audit_id=1,
        agent_prompt="",
        agent_prompt_tokens=0,
        checkpoint_required=False,
    )
    defaults.update(overrides)
    return ContextBundle(**defaults)


class TestContextBundleMandatoryUncertainty:
    def test_none_uncertainty_raises_value_error(self):
        with pytest.raises((ValueError, TypeError)):
            _minimal_bundle(uncertainty=None)

    def test_uncertainty_below_zero_raises(self):
        with pytest.raises(ValueError):
            _minimal_bundle(uncertainty=-0.1)

    def test_uncertainty_above_one_raises(self):
        with pytest.raises(ValueError):
            _minimal_bundle(uncertainty=1.1)

    def test_uncertainty_zero_is_valid(self):
        b = _minimal_bundle(uncertainty=0.0)
        assert b.uncertainty == 0.0

    def test_uncertainty_one_is_valid(self):
        b = _minimal_bundle(uncertainty=1.0)
        assert b.uncertainty == 1.0

    def test_uncertainty_stored_correctly(self):
        b = _minimal_bundle(uncertainty=0.42)
        assert b.uncertainty == 0.42

    def test_uncertainty_boundary_just_below_one(self):
        b = _minimal_bundle(uncertainty=0.9999)
        assert b.uncertainty == pytest.approx(0.9999)

    def test_uncertainty_boundary_just_above_zero(self):
        b = _minimal_bundle(uncertainty=0.0001)
        assert b.uncertainty == pytest.approx(0.0001)


class TestContextBundleMandatoryReasoningTrace:
    def test_empty_tuple_raises_value_error(self):
        with pytest.raises(ValueError, match="reasoning_trace"):
            _minimal_bundle(reasoning_trace=())

    def test_single_element_trace_valid(self):
        b = _minimal_bundle(reasoning_trace=("one reason",))
        assert len(b.reasoning_trace) == 1

    def test_multiple_elements_valid(self):
        b = _minimal_bundle(reasoning_trace=("a", "b", "c"))
        assert len(b.reasoning_trace) == 3

    def test_trace_elements_are_strings(self):
        b = _minimal_bundle(reasoning_trace=("query: test", "facts: 5"))
        assert all(isinstance(e, str) for e in b.reasoning_trace)


class TestContextBundleImmutability:
    def test_bundle_is_frozen(self):
        b = _minimal_bundle()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            b.uncertainty = 0.9  # type: ignore[misc]

    def test_facts_tuple_is_frozen(self):
        b = _minimal_bundle()
        assert isinstance(b.facts, tuple)

    def test_edges_tuple_is_frozen(self):
        b = _minimal_bundle()
        assert isinstance(b.edges, tuple)

    def test_excluded_tuple_is_frozen(self):
        b = _minimal_bundle()
        assert isinstance(b.excluded, tuple)

    def test_reasoning_trace_tuple_is_frozen(self):
        b = _minimal_bundle()
        assert isinstance(b.reasoning_trace, tuple)

    def test_schema_version_default(self):
        b = _minimal_bundle()
        assert b.schema_version == "2.0"

    def test_schema_version_is_string(self):
        b = _minimal_bundle()
        assert isinstance(b.schema_version, str)


class TestContextBundleAgentPrompt:
    def test_agent_prompt_required_when_facts_present(self):
        fact = TypedFact(
            fact_id="f1", subject="s", predicate="p", object_value="o",
            source="src", source_type=SourceType.USER, classification="0",
            taint_labels=(), ingested_at=_now(), provenance_id="prov-1",
        )
        with pytest.raises(ValueError, match="agent_prompt"):
            _minimal_bundle(facts=(fact,), agent_prompt="")

    def test_agent_prompt_optional_when_no_facts(self):
        b = _minimal_bundle(facts=(), agent_prompt="")
        assert b.agent_prompt == ""

    def test_agent_prompt_stored_correctly(self):
        b = _minimal_bundle(agent_prompt="## Context for: test")
        assert "Context for" in b.agent_prompt


class TestTypedFact:
    def _make_fact(self, **overrides) -> TypedFact:
        defaults = dict(
            fact_id="fact-1",
            subject="user:alice",
            predicate="schema:name",
            object_value="Alice",
            source="profile",
            source_type=SourceType.USER,
            classification="UNCLASSIFIED",
            taint_labels=(),
            ingested_at=_now(),
            provenance_id="prov-1",
        )
        defaults.update(overrides)
        return TypedFact(**defaults)

    def test_fact_is_frozen(self):
        f = self._make_fact()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            f.subject = "user:bob"  # type: ignore[misc]

    def test_taint_labels_is_tuple(self):
        f = self._make_fact(taint_labels=(TaintLabel.READS_PRIVATE,))
        assert TaintLabel.READS_PRIVATE in f.taint_labels

    def test_source_type_enum(self):
        f = self._make_fact(source_type=SourceType.TOOL)
        assert f.source_type == SourceType.TOOL

    def test_source_type_inference(self):
        f = self._make_fact(source_type=SourceType.INFERENCE)
        assert f.source_type == SourceType.INFERENCE

    def test_source_type_system(self):
        f = self._make_fact(source_type=SourceType.SYSTEM)
        assert f.source_type == SourceType.SYSTEM

    def test_multiple_taint_labels(self):
        labels = (TaintLabel.READS_PRIVATE, TaintLabel.CAN_EXFILTRATE)
        f = self._make_fact(taint_labels=labels)
        assert len(f.taint_labels) == 2

    def test_provenance_id_stored(self):
        f = self._make_fact(provenance_id="prov-xyz-123")
        assert f.provenance_id == "prov-xyz-123"

    def test_ingested_at_is_datetime(self):
        f = self._make_fact()
        assert isinstance(f.ingested_at, datetime)


class TestWeightedEdge:
    def test_score_out_of_range_raises(self):
        with pytest.raises(ValueError):
            WeightedEdge("a", "b", "rel", 1.0, 2.0, 100.0, score=1.5)

    def test_score_negative_raises(self):
        with pytest.raises(ValueError):
            WeightedEdge("a", "b", "rel", 1.0, 2.0, 100.0, score=-0.1)

    def test_valid_score(self):
        e = WeightedEdge("a", "b", "rel", 1.0, 2.0, 100.0, score=0.7)
        assert e.score == 0.7

    def test_score_zero_valid(self):
        e = WeightedEdge("a", "b", "rel", 1.0, 2.0, 100.0, score=0.0)
        assert e.score == 0.0

    def test_score_one_valid(self):
        e = WeightedEdge("a", "b", "rel", 1.0, 2.0, 100.0, score=1.0)
        assert e.score == 1.0

    def test_edge_is_frozen(self):
        e = WeightedEdge("a", "b", "rel", 1.0, 2.0, 100.0, score=0.5)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            e.score = 0.9  # type: ignore[misc]

    def test_edge_fields_stored(self):
        e = WeightedEdge("from_x", "to_y", "knows", 2.0, 3.0, 500.0, score=0.3)
        assert e.from_id == "from_x"
        assert e.to_id == "to_y"
        assert e.predicate == "knows"
        assert e.distance == 2.0
        assert e.complexity == 3.0
        assert e.size == 500.0


class TestExclusionNote:
    def test_exclusion_note_frozen(self):
        note = ExclusionNote(fact_id="f1", reason="classification_ceiling")
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            note.reason = "other"  # type: ignore[misc]

    def test_exclusion_note_fields(self):
        note = ExclusionNote(fact_id="f42", reason="consent_absent")
        assert note.fact_id == "f42"
        assert note.reason == "consent_absent"


class TestCompletenessEnum:
    def test_completeness_is_str(self):
        assert Completeness.COMPLETE == "complete"
        assert Completeness.PARTIAL == "partial"
        assert Completeness.UNCERTAIN == "uncertain"

    def test_completeness_is_strenum(self):
        from enum import StrEnum
        assert issubclass(Completeness, StrEnum)

    def test_source_type_is_strenum(self):
        from enum import StrEnum
        assert issubclass(SourceType, StrEnum)

    def test_taint_label_is_strenum(self):
        from enum import StrEnum
        assert issubclass(TaintLabel, StrEnum)

    def test_source_type_values(self):
        assert SourceType.USER == "user"
        assert SourceType.TOOL == "tool"
        assert SourceType.INFERENCE == "inference"
        assert SourceType.SYSTEM == "system"

    def test_taint_label_values(self):
        assert TaintLabel.READS_UNTRUSTED == "READS_UNTRUSTED"
        assert TaintLabel.READS_PRIVATE == "READS_PRIVATE"
        assert TaintLabel.CAN_EXFILTRATE == "CAN_EXFILTRATE"


class TestContextBundleAssembledAt:
    def test_assembled_at_is_datetime(self):
        b = _minimal_bundle()
        assert isinstance(b.assembled_at, datetime)

    def test_assembled_at_is_timezone_aware(self):
        b = _minimal_bundle()
        assert b.assembled_at.tzinfo is not None

    def test_consent_ref_stored(self):
        b = _minimal_bundle(consent_ref="urn:aevum:consent:alice")
        assert b.consent_ref == "urn:aevum:consent:alice"

    def test_purpose_stored(self):
        b = _minimal_bundle(purpose="customer-support")
        assert b.purpose == "customer-support"

    def test_audit_id_stored(self):
        b = _minimal_bundle(audit_id=42)
        assert b.audit_id == 42

    def test_checkpoint_required_default_false(self):
        b = _minimal_bundle(checkpoint_required=False)
        assert not b.checkpoint_required

    def test_checkpoint_required_can_be_true(self):
        b = _minimal_bundle(checkpoint_required=True)
        assert b.checkpoint_required
