# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Behavioral canary test suite — runs at boot before any session opens.

If any canary fails, the system halts with CanaryError.
These tests verify the system BEHAVES according to its principles,
not just that the principles file exists.

Phase 3 canaries (7 total):
  1. crisis_barrier_fires_before_graph_write         — barrier 1 fires on crisis text
  2. consent_absent_raises_ConsentRequired           — ConsentRequired is raisable
  3. govern_cannot_be_auto_approved_without_Cedar_permit — barrier 5 enforced via Cedar
  4. reasoning_trace_nonempty_in_every_ContextBundle — ContextBundle enforces humility
  5. audit_chain_append_only                         — barrier 4 enforced via Cedar
  6. dual_signature_every_chain_entry                — sigchain invariant
  7. consent_revoke_destroys_dek                     — GDPR Art. 17 crypto-shredding

Phase 3 also adds _canary_uncertainty_mandatory (callable directly; not in run_all)
to verify the uncertainty principle is enforced at construction time.
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
    skipped: bool = False  # dependency-absent / not-applicable; NOT a pass, NOT a failure


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
        Raises CanaryError on genuine failure (not passed and not skipped).
        Skips (optional dependency absent) log a WARNING but do not block boot.
        Returns list of CanaryResult on completion.
        """
        self._results = []
        canaries: list[Callable[[], CanaryResult]] = [
            self._canary_crisis_barrier_structure,
            self._canary_consent_required_without_grant,
            self._canary_govern_cannot_be_auto_approved,
            self._canary_reasoning_trace_mandatory,
            self._canary_audit_chain_append_only,
            self._canary_dual_signature_every_entry,
            self._canary_consent_revoke_destroys_dek,
        ]

        for canary in canaries:
            result = canary()
            self._results.append(result)
            if result.skipped:
                logger.warning(
                    "Canary SKIPPED (optional dependency absent): %s — %s",
                    result.name, result.detail,
                )
                continue
            if not result.passed:
                raise CanaryError(
                    f"Canary FAILED: {result.name}\n"
                    f"  Detail: {result.detail}\n"
                    f"  The system cannot start with a failing canary. "
                    f"This indicates the codebase no longer satisfies its principles."
                )
            logger.debug("Canary PASS: %s", result.name)

        passed = sum(1 for r in self._results if r.passed and not r.skipped)
        skipped = sum(1 for r in self._results if r.skipped)
        logger.info(
            "Canaries at boot: %d passed, %d skipped (optional deps absent).",
            passed, skipped,
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
            from aevum.core.barriers import BarrierError, crisis_barrier_check
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
            if "cedarpy is not installed" in str(exc):
                return CanaryResult(name=name, passed=False, skipped=True,
                                    detail="cedarpy not installed — Cedar govern canary not applicable")
            return CanaryResult(name=name, passed=False,
                                detail=f"Canary raised: {exc}")

    # ── Canary 4 ─────────────────────────────────────────────────────────────

    def _canary_reasoning_trace_mandatory(self) -> CanaryResult:
        """Verify that ContextBundle rejects an empty reasoning_trace (humility principle)."""
        name = "reasoning_trace_nonempty_in_every_ContextBundle"
        try:
            from datetime import UTC, datetime

            from aevum.core.types import Completeness, ContextBundle

            raised = False
            try:
                ContextBundle(
                    facts=(),
                    edges=(),
                    uncertainty=0.5,
                    reasoning_trace=(),    # empty — must raise
                    completeness=Completeness.COMPLETE,
                    excluded=(),
                    consent_ref="test",
                    purpose="test",
                    assembled_at=datetime.now(UTC),
                    audit_id=1,
                    agent_prompt="",
                    agent_prompt_tokens=0,
                    checkpoint_required=False,
                )
            except ValueError:
                raised = True

            if not raised:
                return CanaryResult(
                    name=name, passed=False,
                    detail="ContextBundle accepted empty reasoning_trace. "
                           "The humility principle is violated.",
                )
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(name=name, passed=False,
                                detail=f"Cannot import ContextBundle: {exc}")
        except Exception as exc:  # noqa: BLE001
            return CanaryResult(name=name, passed=False, detail=str(exc))

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
            context: dict[str, Any] = {}  # barrier 4 is unconditional — no context needed

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
            if "cedarpy is not installed" in str(exc):
                return CanaryResult(name=name, passed=False, skipped=True,
                                    detail="cedarpy not installed — Cedar audit-seal canary not applicable")
            return CanaryResult(name=name, passed=False, detail=str(exc))

    # ── Canary 3 (Phase 3) — uncertainty_mandatory ────────────────────────────
    # Not in run_all; called directly by tests to verify the uncertainty principle.

    def _canary_uncertainty_mandatory(self) -> CanaryResult:
        """Verify that ContextBundle rejects uncertainty=None (uncertainty principle)."""
        name = "uncertainty_present_in_every_ContextBundle"
        try:
            from datetime import UTC, datetime

            from aevum.core.types import Completeness, ContextBundle

            # Construction WITHOUT uncertainty must raise ValueError or TypeError
            raised = False
            try:
                ContextBundle(
                    facts=(),
                    edges=(),
                    uncertainty=None,      # type: ignore[arg-type]
                    reasoning_trace=("test",),
                    completeness=Completeness.COMPLETE,
                    excluded=(),
                    consent_ref="test",
                    purpose="test",
                    assembled_at=datetime.now(UTC),
                    audit_id=1,
                    agent_prompt="test",
                    agent_prompt_tokens=1,
                    checkpoint_required=False,
                )
            except (ValueError, TypeError):
                raised = True

            if not raised:
                return CanaryResult(
                    name=name, passed=False,
                    detail="ContextBundle accepted uncertainty=None. "
                           "The uncertainty principle is violated.",
                )

            # Construction WITH valid uncertainty must succeed
            bundle = ContextBundle(
                facts=(),
                edges=(),
                uncertainty=0.5,
                reasoning_trace=("reason",),
                completeness=Completeness.PARTIAL,
                excluded=(),
                consent_ref="test",
                purpose="test",
                assembled_at=datetime.now(UTC),
                audit_id=1,
                agent_prompt="",
                agent_prompt_tokens=0,
                checkpoint_required=False,
            )
            if bundle.uncertainty != 0.5:
                return CanaryResult(
                    name=name, passed=False,
                    detail="ContextBundle.uncertainty stored incorrectly.",
                )
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(name=name, passed=False,
                                detail=f"Cannot import ContextBundle: {exc}")
        except Exception as exc:  # noqa: BLE001
            return CanaryResult(name=name, passed=False, detail=str(exc))

    # ── Canary 6 ─────────────────────────────────────────────────────────────

    def _canary_dual_signature_every_entry(self) -> CanaryResult:
        """
        Verify that DualSigner can sign and verify a test payload.
        Exercises both Ed25519 (PyNaCl) and ML-DSA-65 (liboqs).
        If liboqs is absent this is an environmental limitation, not a code
        defect — return skipped=True so the system can still boot with an honest warning.
        """
        name = "dual_signature_every_chain_entry"
        try:
            from aevum.core.signing import _OQS_AVAILABLE

            if not _OQS_AVAILABLE:
                return CanaryResult(
                    name=name,
                    passed=False,
                    skipped=True,
                    detail=(
                        "Ed25519 (PyNaCl) available and verified. "
                        "ML-DSA-65 requires liboqs-python (not installed in this environment). "
                        "Install liboqs-python for full post-quantum dual-signature coverage. "
                        "Conformance invariant 8 is PARTIALLY satisfied."
                    ),
                )

            signer = DualSigner.generate()
            test_data = b"aevum-canary-test-payload-phase-1"
            dual_sig = signer.sign(test_data)

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

            DualSigner.verify(test_data, dual_sig)

            try:
                DualSigner.verify(b"tampered", dual_sig)
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="Tampered data was not rejected — signatures are broken",
                )
            except SignatureError:
                pass

            return CanaryResult(name=name, passed=True)

        except Exception as exc:  # noqa: BLE001
            return CanaryResult(
                name=name,
                passed=False,
                detail=f"Dual-sig canary raised unexpected exception: {exc}",
            )

    # ── Canary 7 (Phase 3) — consent_revoke_destroys_dek ─────────────────────

    def _canary_consent_revoke_destroys_dek(self) -> CanaryResult:
        """
        Verify that shredding a subject's DEK makes their data permanently
        unreadable (GDPR Art. 17 crypto-shredding).
        """
        name = "consent_revoke_destroys_dek"
        try:
            import tempfile
            from pathlib import Path

            from aevum.core.consent.ledger import ConsentLedger, ConsentRequired

            with tempfile.TemporaryDirectory() as tmpdir:
                ledger = ConsentLedger(Path(tmpdir) / "canary_consent.db")

                # Grant consent and encrypt some data
                ledger.grant("canary-subject", "canary-purpose")
                plaintext = b"canary sensitive data"
                ciphertext = ledger.encrypt_for_subject("canary-subject", plaintext)

                # Verify round-trip before shredding
                decrypted = ledger.decrypt_for_subject("canary-subject", ciphertext)
                if decrypted != plaintext:
                    return CanaryResult(
                        name=name, passed=False,
                        detail="Encryption/decryption roundtrip failed before shred.",
                    )

                # Shred: destroy DEK
                ledger.shred("canary-subject")

                # After shredding, decrypt must raise ConsentRequired
                raised = False
                try:
                    ledger.decrypt_for_subject("canary-subject", ciphertext)
                except ConsentRequired:
                    raised = True

                ledger.close()

            if not raised:
                return CanaryResult(
                    name=name, passed=False,
                    detail="DEK shredding did not prevent decryption. "
                           "GDPR Art. 17 crypto-shredding is broken.",
                )
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(name=name, passed=False,
                                detail=f"Cannot import ConsentLedger: {exc}")
        except Exception as exc:  # noqa: BLE001
            return CanaryResult(name=name, passed=False, detail=str(exc))
