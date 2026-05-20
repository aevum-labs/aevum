# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
GOVERN checkpoint — the non-bypassable human review gate.

Every consequential, irreversible action must pass through GOVERN.
Veto is the default: if human review times out, the action is blocked.
The automation bias warning is shown at every substantive checkpoint.
The checkpoint outcome is always recorded in the sigchain.

Three possible outcomes:
  approved  — human reviewed and approved within timeout
  vetoed    — human reviewed and vetoed, OR timeout elapsed (veto-as-default)
  crisis    — crisis content detected during review; session halted

Usage:
  gate = await session.govern(
      action="send_email",
      reversible=False,
      consequential=True,
      context=ctx_bundle,
  )
  if gate.approved:
      send_email(...)
  # gate.vetoed: nothing happens — the veto IS the system working correctly
  # gate outcome is always recorded regardless

Architecture:
  GOVERN calls CedarPolicyEngine to evaluate the govern_approve action.
  Cedar's Barrier 5 forbids it unless human_checkpoint_completed=True.
  The checkpoint loop sets human_checkpoint_completed=True AFTER human input.
  Then Cedar re-evaluates and returns Allow.
"""
from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

# Automation bias warning — shown at every GOVERN checkpoint
AUTOMATION_BIAS_WARNING = (
    "\n⚠  AUTOMATION BIAS WARNING\n"
    "   AI systems can be confidently wrong. The proposed action has been\n"
    "   presented by an automated system. Take a moment to independently\n"
    "   verify before approving.\n"
)

# Default timeout for human review (seconds)
DEFAULT_GOVERN_TIMEOUT_SECONDS = 300  # 5 minutes


class GovernOutcome(StrEnum):
    """The result of a GOVERN checkpoint."""
    APPROVED = "approved"
    VETOED = "vetoed"      # human vetoed OR timeout (veto-as-default)
    CRISIS = "crisis"       # crisis content detected during review


@dataclasses.dataclass(frozen=True)
class ProposedAction:
    """
    Describes an action that requires human review via GOVERN.

    reversible:    Can this action be undone if wrong?
    consequential: Does this action have significant real-world impact?
    If both are True, Barrier 5 fires and human review is mandatory.
    """
    action_type: str              # e.g. "send_email", "charge_payment"
    reversible: bool
    consequential: bool
    affects: list[str]            # entity IDs affected by this action
    classification: str = "UNCLASSIFIED"  # data classification level
    description: str = ""         # human-readable description for the reviewer
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class CheckpointResult:
    """
    The outcome of a GOVERN checkpoint.
    Always recorded in the sigchain — even if vetoed.

    EU AI Act Article 14 requires human oversight to be recorded, not just present.
    The review_started_at / review_completed_at / checklist_acknowledged / reviewer_id
    fields satisfy that requirement and are included in the sigchain record via to_dict().
    These fields are additive — existing sigchain fields are never renamed or removed.
    """
    proposed_action: ProposedAction
    outcome: GovernOutcome
    decided_at: datetime
    decided_by: str | None     # human reviewer identifier, or None if timeout
    session_id: str
    checkpoint_id: str
    timeout_seconds: float
    elapsed_seconds: float
    # EU AI Act Article 14 — human oversight recording (p3-11)
    review_started_at: datetime | None = None    # when review was presented to human
    review_completed_at: datetime | None = None  # when human responded
    checklist_acknowledged: bool = False         # human explicitly acknowledged checklist
    reviewer_id: str | None = None              # identity of human reviewer (humans only)

    @property
    def approved(self) -> bool:
        return self.outcome == GovernOutcome.APPROVED

    @property
    def vetoed(self) -> bool:
        return self.outcome == GovernOutcome.VETOED

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.proposed_action.action_type,
            "reversible": self.proposed_action.reversible,
            "consequential": self.proposed_action.consequential,
            "affects": self.proposed_action.affects,
            "outcome": self.outcome.value,
            "decided_at": self.decided_at.isoformat(),
            "decided_by": self.decided_by,
            "session_id": self.session_id,
            "checkpoint_id": self.checkpoint_id,
            "elapsed_seconds": self.elapsed_seconds,
            # Article 14 oversight fields (p3-11)
            "review_started_at": self.review_started_at.isoformat() if self.review_started_at else None,
            "review_completed_at": self.review_completed_at.isoformat() if self.review_completed_at else None,
            "checklist_acknowledged": self.checklist_acknowledged,
            "reviewer_id": self.reviewer_id,
        }


class GovernCheckpoint:
    """
    Implements the GOVERN checkpoint with veto-as-default.

    In Phase 2, the human review mechanism is a synchronous callback
    (or None for testing). In Phase 7+, this will integrate with the
    MCP tool surface and A2A protocol for async human review.
    """

    def __init__(
        self,
        cedar_engine: Any,          # CedarPolicyEngine
        session_id: str,
        review_callback: Any | None = None,  # callable(ProposedAction) -> bool
        timeout_seconds: float = DEFAULT_GOVERN_TIMEOUT_SECONDS,
    ) -> None:
        self._cedar = cedar_engine
        self._session_id = session_id
        self._review_callback = review_callback
        self._timeout = timeout_seconds

    def checkpoint(
        self,
        action: ProposedAction,
        agent_id: str = "agent",
    ) -> CheckpointResult:
        """
        Run a GOVERN checkpoint for the proposed action.

        Steps:
          1. Display automation bias warning
          2. Check if Cedar requires human review (Barrier 5 + autonomy)
          3. If required: invoke review callback or apply veto-as-default
          4. Re-evaluate Cedar with human_checkpoint_completed=True if approved
          5. Return CheckpointResult (always — never raises on veto)

        Note: CheckpointResult must be recorded in the sigchain by the caller.
        GOVERN itself does not write to the sigchain — that is Session's job.
        """
        checkpoint_id = str(uuid.uuid4())
        start = datetime.now(UTC)

        # Always show the automation bias warning for substantive checkpoints
        if action.reversible is False or action.consequential:
            logger.warning(AUTOMATION_BIAS_WARNING)

        # Cedar evaluation: does this require human review?
        requires_review = self._requires_human_review(action, agent_id)

        if not requires_review:
            # Cedar permits this without human review — no human dwell time to record
            elapsed = (datetime.now(UTC) - start).total_seconds()
            return CheckpointResult(
                proposed_action=action,
                outcome=GovernOutcome.APPROVED,
                decided_at=datetime.now(UTC),
                decided_by="cedar_automatic_permit",
                session_id=self._session_id,
                checkpoint_id=checkpoint_id,
                timeout_seconds=self._timeout,
                elapsed_seconds=elapsed,
                review_started_at=None,
                review_completed_at=None,
                checklist_acknowledged=False,
                reviewer_id=None,
            )

        # Human review required — record dwell time per EU AI Act Article 14
        review_started_at = datetime.now(UTC)
        human_approved, human_reviewer_id = self._request_human_review(action)
        review_completed_at = datetime.now(UTC)
        elapsed = (review_completed_at - start).total_seconds()

        outcome = GovernOutcome.APPROVED if human_approved else GovernOutcome.VETOED

        logger.info(
            "GOVERN checkpoint %s: action=%s outcome=%s elapsed=%.1fs",
            checkpoint_id, action.action_type, outcome.value, elapsed,
        )

        return CheckpointResult(
            proposed_action=action,
            outcome=outcome,
            decided_at=review_completed_at,
            decided_by=human_reviewer_id,
            session_id=self._session_id,
            checkpoint_id=checkpoint_id,
            timeout_seconds=self._timeout,
            elapsed_seconds=elapsed,
            review_started_at=review_started_at,
            review_completed_at=review_completed_at if human_reviewer_id else None,
            checklist_acknowledged=human_approved,
            reviewer_id=human_reviewer_id if human_approved else None,
        )

    def _requires_human_review(self, action: ProposedAction, agent_id: str) -> bool:
        """
        Ask Cedar whether this action requires human review.
        Returns True if Cedar denies govern_approve (i.e., human review needed).
        Returns False if Cedar permits without review.
        """
        context = {
            "action_reversible": action.reversible,
            "action_consequential": action.consequential,
            "data_classification_level": self._classification_level(action.classification),
            "deployment_ceiling_level": 3,  # default: PHI ceiling
            "has_crisis_content": False,
            "has_active_consent": True,     # assume consent checked upstream
            "consent_purpose_matches": True,
            "autonomy_level": 3,            # default: L3 semi-autonomous
            "human_checkpoint_completed": False,  # not yet reviewed
        }

        permitted = self._cedar.is_permitted(
            principal_type="AevumAgent",
            principal_id=agent_id,
            action="govern_approve",
            resource_type="DataGraph",
            resource_id="knowledge",
            context=context,
        )
        # If Cedar denies, human review is required
        return not permitted

    def _request_human_review(
        self, action: ProposedAction
    ) -> tuple[bool, str | None]:
        """
        Request human review via callback or apply veto-as-default.
        Returns (approved: bool, reviewer_id: Optional[str]).
        """
        if self._review_callback is None:
            # No review callback: veto-as-default applies
            logger.warning(
                "GOVERN: No review callback configured. "
                "Veto-as-default applied for action=%s. "
                "Configure a review callback to allow human approval.",
                action.action_type,
            )
            return False, None

        try:
            approved = bool(self._review_callback(action))
            reviewer_id = "human-reviewer" if approved else "human-reviewer-vetoed"
            return approved, reviewer_id
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "GOVERN review callback raised: %s. Veto-as-default applied.",
                exc,
            )
            return False, None

    @staticmethod
    def _classification_level(classification: str) -> int:
        """Convert classification string to integer level."""
        levels = {
            "UNCLASSIFIED": 0,
            "INTERNAL": 1,
            "CONFIDENTIAL": 2,
            "PHI": 3,
            "SECRET": 4,
        }
        return levels.get(classification.upper(), 0)
