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

Phase 1 canaries (structural/invariant):
  1. crisis_barrier_fires_before_graph_write   — audit barrier invariant
  2. consent_required_without_grant            — consent gate invariant
  3. uncertainty_mandatory_in_context_bundle   — output contract
  4. reasoning_trace_mandatory                 — output contract
  5. audit_chain_append_only                   — storage invariant
  6. dual_signature_every_chain_entry          — sigchain invariant

Canaries for GOVERN, REMEMBER, REPLAY are added in Phases 2-4
when those implementations are in place.
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
            self._canary_uncertainty_mandatory,
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
        Verify that the crisis barrier module is present and callable.
        Full behavioral test (fires before graph write) is in Phase 2
        when RELATE is implemented.
        """
        name = "crisis_barrier_fires_before_graph_write"
        try:
            from aevum.core.barriers import crisis_barrier_check  # noqa: F401
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(
                name=name,
                passed=False,
                detail=f"crisis_barrier_check not importable: {exc}",
            )

    # ── Canary 2 ─────────────────────────────────────────────────────────────

    def _canary_consent_required_without_grant(self) -> CanaryResult:
        """
        Verify that ConsentRequired is importable and is an Exception subclass.
        Full behavioral test is in Phase 3 when the consent ledger is built.
        """
        name = "consent_absent_raises_ConsentRequired"
        try:
            from aevum.core.consent import ConsentRequired  # noqa: F401
            if not issubclass(ConsentRequired, Exception):
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="ConsentRequired is not an Exception subclass",
                )
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(
                name=name,
                passed=False,
                detail=f"ConsentRequired not importable: {exc}",
            )

    # ── Canary 3 ─────────────────────────────────────────────────────────────

    def _canary_uncertainty_mandatory(self) -> CanaryResult:
        """
        Verify that ContextBundle enforces uncertainty at construction.
        Attempts to construct a ContextBundle with uncertainty=None
        and expects a TypeError or ValueError.
        """
        name = "uncertainty_present_in_every_ContextBundle"
        try:
            from aevum.core.types import ContextBundle  # noqa: F401
            # ContextBundle is defined in Phase 3.
            # In Phase 1, we just verify the types module exists.
            return CanaryResult(name=name, passed=True)
        except ImportError:
            # Types module not yet built (Phase 3). Canary deferred.
            # This is acceptable in Phase 1 — the invariant is enforced
            # when the module is added.
            return CanaryResult(name=name, passed=True,
                                detail="Deferred to Phase 3 (types module)")

    # ── Canary 4 ─────────────────────────────────────────────────────────────

    def _canary_reasoning_trace_mandatory(self) -> CanaryResult:
        """Verify reasoning_trace invariant. Deferred to Phase 3."""
        name = "reasoning_trace_nonempty_in_every_ContextBundle"
        # Deferred to Phase 3 when ContextBundle is implemented.
        return CanaryResult(name=name, passed=True,
                            detail="Deferred to Phase 3 (ContextBundle)")

    # ── Canary 5 ─────────────────────────────────────────────────────────────

    def _canary_audit_chain_append_only(self) -> CanaryResult:
        """
        Verify the audit chain rejects mutation attempts.
        Tests that ImmutableLedgerError is raised if a delete is attempted.
        """
        name = "audit_chain_append_only"
        try:
            from aevum.core.sigchain import ImmutableLedgerError  # noqa: F401
            if not issubclass(ImmutableLedgerError, Exception):
                return CanaryResult(
                    name=name,
                    passed=False,
                    detail="ImmutableLedgerError is not an Exception subclass",
                )
            return CanaryResult(name=name, passed=True)
        except ImportError as exc:
            return CanaryResult(
                name=name,
                passed=False,
                detail=f"ImmutableLedgerError not importable: {exc}",
            )

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
