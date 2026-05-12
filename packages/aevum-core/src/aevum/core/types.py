# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Core types for the Aevum memory layer.

All types are frozen dataclasses. ContextBundle enforces its invariants
at construction time — a missing uncertainty or empty reasoning_trace
is a construction error, not a runtime warning.
"""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


# ── Enumerations ──────────────────────────────────────────────────────────────

class Completeness(StrEnum):
    """
    How complete is the assembled context relative to what was available?
    COMPLETE: all relevant facts included.
    PARTIAL: some facts were excluded (see ExclusionNote).
    UNCERTAIN: coverage cannot be determined.
    """
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNCERTAIN = "uncertain"


class SourceType(StrEnum):
    """Where did a TypedFact originate?"""
    USER = "user"
    TOOL = "tool"
    INFERENCE = "inference"
    SYSTEM = "system"


class TaintLabel(StrEnum):
    """Taint labels for trifecta enforcement."""
    READS_UNTRUSTED = "READS_UNTRUSTED"
    READS_PRIVATE = "READS_PRIVATE"
    CAN_EXFILTRATE = "CAN_EXFILTRATE"


# ── Core types ────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class TypedFact:
    """
    A single fact in the knowledge graph.
    Immutable. Every fact has provenance.
    """
    fact_id: str
    subject: str           # entity this fact is about
    predicate: str         # relationship type (CURIE or IRI)
    object_value: str      # the value
    source: str            # source identifier
    source_type: SourceType
    classification: str    # data classification level
    taint_labels: tuple[str, ...]
    ingested_at: datetime
    provenance_id: str     # links to provenance named graph entry


@dataclasses.dataclass(frozen=True)
class WeightedEdge:
    """
    An edge between two entities in the knowledge graph, with 3-axis weight.

    The three axes (Distance, Complexity, Size) are combined into a single
    relevance score. A score of 1.0 means maximally relevant; 0.0 means
    irrelevant.
    """
    from_id: str
    to_id: str
    predicate: str
    distance: float    # graph distance from query node (lower = more relevant)
    complexity: float  # node degree (lower = simpler, more focused)
    size: float        # content length in characters (log-scaled)
    score: float       # combined relevance score (0.0-1.0)

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(
                f"WeightedEdge.score must be in [0.0, 1.0], got {self.score}"
            )


@dataclasses.dataclass(frozen=True)
class ExclusionNote:
    """Records why a fact was excluded from the assembled context."""
    fact_id: str
    reason: str   # e.g. "classification_ceiling", "consent_absent", "relevance_below_threshold"


@dataclasses.dataclass(frozen=True)
class ContextBundle:
    """
    The output contract of NAVIGATE.

    uncertainty and reasoning_trace are MANDATORY.
    Construction fails (ValueError) if either is absent or empty.
    This is enforced in __post_init__, not at runtime.

    The agent_prompt field is ready for direct LLM injection.
    """
    facts: tuple[TypedFact, ...]
    edges: tuple[WeightedEdge, ...]
    uncertainty: float             # MANDATORY — 0.0 (certain) to 1.0 (max uncertainty)
    reasoning_trace: tuple[str, ...]  # MANDATORY — must be non-empty
    completeness: Completeness
    excluded: tuple[ExclusionNote, ...]
    consent_ref: str
    purpose: str
    assembled_at: datetime
    audit_id: int                  # sigchain entry ID for this context assembly
    agent_prompt: str              # ready for LLM injection
    agent_prompt_tokens: int
    checkpoint_required: bool
    schema_version: str = "2.0"

    def __post_init__(self) -> None:
        # uncertainty is mandatory — this is a principle (regulated: uncertainty)
        if self.uncertainty is None:
            raise ValueError(
                "ContextBundle.uncertainty is mandatory. "
                "A system that presents answers without visible uncertainty "
                "violates the uncertainty principle."
            )
        if not 0.0 <= self.uncertainty <= 1.0:
            raise ValueError(
                f"ContextBundle.uncertainty must be in [0.0, 1.0], "
                f"got {self.uncertainty}"
            )

        # reasoning_trace is mandatory — this is a principle (regulated: humility)
        if not self.reasoning_trace:
            raise ValueError(
                "ContextBundle.reasoning_trace must be non-empty. "
                "The system presents candidates, not conclusions. "
                "An empty reasoning trace violates the humility principle."
            )

        # agent_prompt must be non-empty if facts exist
        if self.facts and not self.agent_prompt:
            raise ValueError(
                "ContextBundle.agent_prompt must be set when facts are present."
            )
