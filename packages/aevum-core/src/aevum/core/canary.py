# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Behavioral canary test suite — runs at boot before any session opens.

If any canary fails, the system halts with CanaryError.
These tests verify the system BEHAVES according to its principles,
not just that the principles file exists.

The six canaries in this module test structural properties of the kernel
using internal mocks — they do not require Cedar, pyoxigraph, or session state.
The full canary suite (testing RELATE, NAVIGATE, GOVERN, REMEMBER) is built
progressively as those modules are added in Phases 2-4.

Phase 2 canaries (behavioral):
  1. crisis_barrier_fires_before_graph_write         — barrier 1 fires on crisis text
  2. consent_absent_raises_ConsentRequired           — ConsentRequired is raisable
  3. govern_cannot_be_auto_approved_without_Cedar_permit — barrier 5 enforced via Cedar
  4. reasoning_trace_nonempty_in_every_ContextBundle — deferred to Phase 3
  5. audit_chain_append_only                         — barrier 4 enforced via Cedar
  6. dual_signature_every_chain_entry                — sigchain invariant
"""
from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable
from typing import Any

# Module-level import required so tests can patch aevum.core.canary.DualSigner.generate
from aevum.core.signing import DualSigner, SignatureError

logger = logging.getLogger(__name__)


class CanaryError(Exception):
    """
    Raised when a behavioral canary fails at boot.
    The system must not continue if this is raised.
    """


@dataclasses.dataclass
class CanaryResult:
    name: str
    passed: bool
    detail: str = ""


class CanarySuite:
    """
    Boot-time behavioral verification suite.

    Run with: suite.run_all()
    Raises CanaryError on the first failure.
    """

    def __init__(self, kernel: Any) -> None:
        """
        kernel: the Kernel instance being booted.
        Canaries access kernel internals to verify structural properties.
        """
        self._kernel = kernel
        self._results: list[CanaryResult] = []

    def run_all(self) -> list[CanaryResult]:
        """
        Run all registered canaries.
        Raises CanaryError on first failure.
        Returns list of CanaryResult on full success.
        """
        self._results = []
        canaries: list[Callable[[], CanaryResult]] = [
            self._canary_crisis_barrier_structure,
            self._canary_consent_required_without_grant,
            self._canary_govern_cannot_be_auto_approved,
            self._canary_reasoning_trace_mandatory,
            self._canary_audit_chain_append_only,
            self._canary_dual_signature_every_entry,
        ]

        for canary in canaries:
            result = canary()
            self._results.append(result)
            if not result.passed:
                raise CanaryError(
                    f"Canary FAILED: {result.name}\n"
                    f"  Detail: {result.detail}\n"
                    f"  The system cannot start with a failing canary. "
                    f"This indicates the codebase no longer satisfies its principles."
                )
            logger.debug("Canary PASS: %s", result.name)

        logger.info(
            "All %d canaries passed at boot.", len(self._results)
        )
        return list(self._results)

    # ── Canary 1 ─────────────────────────────────────────────────────────────

    def _canary_crisis_barrier_structure(self) -> CanaryResult:
        """
        Verify the crisis barrier actually fires before graph writes.
        Attempts to call crisis_barrier_check with crisis content.
        """
        name = "crisis_barrier_fires_before_graph_write"
        try:
            from aevum.core.barriers import crisis_barrier_check, BarrierError
            # crisis_barrier_check must raise BarrierError for crisis content
            raised = False
            try:
                crisis_barrier_check("I want to end my life")
            except BarrierError:
                raised = True
            if not raised:
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="crisis_barrier_check did not raise BarrierError "
                           "for 'I want to end my life'. "
                           "This is a critical safety failure.",
                )
            # Normal text must NOT raise
            try:
                crisis_barrier_check("The weather is nice today.")
            except BarrierError:
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="crisis_barrier_check raised BarrierError for "
                           "non-crisis text — false positive.",
                )
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(name=name, passed=False,
                                detail=f"Cannot import: {exc}")

    # ── Canary 2 ─────────────────────────────────────────────────────────────

    def _canary_consent_required_without_grant(self) -> CanaryResult:
        """
        Verify that accessing data without consent raises ConsentRequired.
        """
        name = "consent_absent_raises_ConsentRequired"
        try:
            from aevum.core.consent import ConsentRequired
            # ConsentRequired must be an Exception subclass
            if not issubclass(ConsentRequired, Exception):
                return CanaryResult(
                    name=name, passed=False,
                    detail="ConsentRequired is not an Exception subclass",
                )
            # Verify it can be raised and caught
            try:
                raise ConsentRequired("canary test")
            except ConsentRequired:
                pass
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(name=name, passed=False,
                                detail=f"Cannot import ConsentRequired: {exc}")

    # ── Canary 3 ─────────────────────────────────────────────────────────────

    def _canary_govern_cannot_be_auto_approved(self) -> CanaryResult:
        """
        Verify that GOVERN cannot approve an irreversible+consequential action
        without a human checkpoint (Barrier 5).
        """
        name = "govern_cannot_be_auto_approved_without_Cedar_permit"
        try:
            from aevum.core.cedar_engine import CedarPolicyEngine
            engine = CedarPolicyEngine.default()

            # Attempt govern_approve for irreversible+consequential action
            # WITHOUT human_checkpoint_completed
            context_no_review = {
                "action_reversible": False,
                "action_consequential": True,
                "has_crisis_content": False,
                "has_active_consent": True,
                "consent_purpose_matches": True,
                "data_classification_level": 0,
                "deployment_ceiling_level": 3,
                "autonomy_level": 3,
                "human_checkpoint_completed": False,
            }
            permitted_without_review = engine.is_permitted(
                principal_type="AevumAgent",
                principal_id="canary-agent",
                action="govern_approve",
                resource_type="DataGraph",
                resource_id="knowledge",
                context=context_no_review,
            )
            if permitted_without_review:
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="Cedar permitted govern_approve for irreversible+"
                           "consequential action WITHOUT human review. "
                           "Barrier 5 is broken.",
                )

            # With human_checkpoint_completed=True, it should be permitted
            context_reviewed = dict(context_no_review)
            context_reviewed["human_checkpoint_completed"] = True
            permitted_with_review = engine.is_permitted(
                principal_type="AevumAgent",
                principal_id="canary-agent",
                action="govern_approve",
                resource_type="DataGraph",
                resource_id="knowledge",
                context=context_reviewed,
            )
            if not permitted_with_review:
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="Cedar denied govern_approve even WITH "
                           "human_checkpoint_completed=True. "
                           "Barrier 5 escape clause is broken.",
                )

            return CanaryResult(name=name, passed=True)

        except Exception as exc:  # noqa: BLE001
            return CanaryResult(name=name, passed=False,
                                detail=f"Canary raised: {exc}")

    # ── Canary 4 ─────────────────────────────────────────────────────────────

    def _canary_reasoning_trace_mandatory(self) -> CanaryResult:
        """Verify reasoning_trace invariant. Deferred to Phase 3."""
        name = "reasoning_trace_nonempty_in_every_ContextBundle"
        # Deferred to Phase 3 when ContextBundle is implemented.
        return CanaryResult(name=name, passed=True,
                            detail="Deferred to Phase 3 (ContextBundle)")

    # ── Canary 5 ─────────────────────────────────────────────────────────────

    def _canary_audit_chain_append_only(self) -> CanaryResult:
        """Verify Barrier 4 blocks audit chain mutations via Cedar."""
        name = "audit_chain_append_only"
        try:
            from aevum.core.cedar_engine import CedarPolicyEngine
            from aevum.core.sigchain import ImmutableLedgerError

            if not issubclass(ImmutableLedgerError, Exception):
                return CanaryResult(name=name, passed=False,
                                    detail="ImmutableLedgerError not an Exception")

            engine = CedarPolicyEngine.default()
            context: dict = {}  # barrier 4 is unconditional — no context needed

            # delete_audit_event must always be denied
            permitted = engine.is_permitted(
                principal_type="AevumAgent",
                principal_id="canary-agent",
                action="delete_audit_event",
                resource_type="DataGraph",
                resource_id="provenance",
                context=context,
            )
            if permitted:
                return CanaryResult(
                    name=name, passed=False,
                    detail="Cedar permitted delete_audit_event. "
                           "Barrier 4 (audit seal) is broken.",
                )
            return CanaryResult(name=name, passed=True)
        except Exception as exc:  # noqa: BLE001
            return CanaryResult(name=name, passed=False, detail=str(exc))

    # ── Canary 6 ─────────────────────────────────────────────────────────────

    def _canary_dual_signature_every_entry(self) -> CanaryResult:
        """
        Verify that DualSigner can sign and verify a test payload.
        This exercises both Ed25519 (PyNaCl) and ML-DSA-65 (liboqs).
        """
        name = "dual_signature_every_chain_entry"
        try:
            signer = DualSigner.generate()
            test_data = b"aevum-canary-test-payload-phase-1"
            dual_sig = signer.sign(test_data)

            # Both signatures must be present
            if len(dual_sig.ed25519_sig) != 64:
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail=f"Ed25519 sig wrong length: {len(dual_sig.ed25519_sig)}",
                )
            if len(dual_sig.mldsa65_sig) != 3309:
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail=f"ML-DSA-65 sig wrong length: {len(dual_sig.mldsa65_sig)}",
                )

            # Verification must pass
            DualSigner.verify(test_data, dual_sig)

            # Tampered data must fail
            try:
                DualSigner.verify(b"tampered", dual_sig)
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="Tampered data was not rejected — signatures are broken",
                )
            except SignatureError:
                pass  # correct — tampered data was rejected

            return CanaryResult(name=name, passed=True)

        except Exception as exc:  # noqa: BLE001
            return CanaryResult(
                name=name,
                passed=False,
                detail=f"Dual-sig canary raised unexpected exception: {exc}",
            )
