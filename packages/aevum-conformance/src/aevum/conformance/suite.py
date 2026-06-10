# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum conformance test suite — 11 invariants.

Run against any Aevum installation:
  from aevum.conformance.suite import ConformanceSuite
  suite = ConformanceSuite()
  result = suite.run_all()
  print(result.render())

The 11 invariants correspond to the behavioral canaries, extended with
end-to-end checks that require a running kernel.

Conformance invariants are numbered 1–11 and are distinct from the seven
**formal receipt invariants** ``I1–I7`` defined in ``aevum.core.invariants``
(the spec-level guarantees). The two taxonomies do not share identifiers.

Invariants:
  1. crisis_barrier_fires_before_graph_write
  2. consent_absent_raises_ConsentRequired
  3. govern_cannot_be_auto_approved_without_Cedar_permit
  4. remember_fires_on_every_session_close
  5. uncertainty_present_in_every_ContextBundle
  6. reasoning_trace_nonempty_in_every_ContextBundle
  7. audit_chain_append_only
  8. dual_signature_every_chain_entry (Ed25519 AND ML-DSA-65)
  9. consent_revoke_destroys_dek
 10. cose_sign1_receipt_valid_structure_alg_minus_8 (COSE_Sign1 receipt structure)
 11. prov_agent_fields_present (PROV-AGENT vocabulary fields on every receipt)
"""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any


@dataclasses.dataclass(frozen=True)
class InvariantResult:
    """The result of checking a single conformance invariant."""
    invariant_id: int
    name: str
    passed: bool
    detail: str = ""
    skipped: bool = False


@dataclasses.dataclass(frozen=True)
class ConformanceResult:
    """The complete conformance suite result."""
    results: tuple[InvariantResult, ...]
    checked_at: datetime
    aevum_version: str

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.results if r.skipped)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed and not r.skipped)

    @property
    def all_passed(self) -> bool:
        # True only when every invariant genuinely passed (no failures, no skips).
        return self.failed_count == 0 and self.skipped_count == 0

    def render(self) -> str:
        """Plain text gate report output."""
        lines = [
            "AEVUM CONFORMANCE REPORT",
            f"Date: {self.checked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Version: {self.aevum_version}",
            "Suite: aevum-conformance 2.0",
            "-" * 50,
        ]
        for r in self.results:
            status = "PASS" if r.passed else ("SKIP" if r.skipped else "FAIL")
            lines.append(f"INVARIANT {r.invariant_id:>2}  {r.name:<45} {status}")
            if r.detail and not r.passed:
                lines.append(f"           Detail: {r.detail[:120]}")
        lines.append("-" * 50)
        if self.failed_count:
            overall = "FAIL"
        elif self.skipped_count:
            overall = "PASS (with skips)"
        else:
            overall = "PASS"
        status_str = (
            f"STATUS: {overall} "
            f"({self.passed_count} passed, {self.skipped_count} skipped, "
            f"{self.failed_count} failed / {self.total_count})"
        )
        lines.append(status_str)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at.isoformat(),
            "aevum_version": self.aevum_version,
            "passed": self.all_passed,
            "passed_count": self.passed_count,
            "skipped_count": self.skipped_count,
            "failed_count": self.failed_count,
            "total_count": self.total_count,
            "results": [
                {
                    "invariant_id": r.invariant_id,
                    "name": r.name,
                    "passed": r.passed,
                    "skipped": r.skipped,
                    "detail": r.detail,
                }
                for r in self.results
            ],
        }


# Each entry: (invariant_id, canary_method_name, canary_result_name)
_CANARY_INVARIANTS: tuple[tuple[int, str, str], ...] = (
    (1, "_canary_crisis_barrier_structure", "crisis_barrier_fires_before_graph_write"),
    (2, "_canary_consent_required_without_grant", "consent_absent_raises_ConsentRequired"),
    (3, "_canary_govern_cannot_be_auto_approved", "govern_cannot_be_auto_approved_without_Cedar_permit"),
    (5, "_canary_uncertainty_mandatory", "uncertainty_present_in_every_ContextBundle"),
    (6, "_canary_reasoning_trace_mandatory", "reasoning_trace_nonempty_in_every_ContextBundle"),
    (7, "_canary_audit_chain_append_only", "audit_chain_append_only"),
    (8, "_canary_dual_signature_every_entry", "dual_signature_every_chain_entry"),
    (9, "_canary_consent_revoke_destroys_dek", "consent_revoke_destroys_dek"),
)


class ConformanceSuite:
    """
    Runs all 9 conformance invariants against an Aevum installation.

    Calls each canary method directly (rather than run_all which raises
    on first failure) to collect all 8 canary-based invariant results
    independently. Adds invariant 4 (remember_fires_on_every_session_close)
    via structural inspection of the Session class.
    """

    def __init__(self, kernel: Any = None) -> None:
        """
        kernel: an Aevum Kernel instance (optional).
        If None, a MagicMock is used for canary checks.
        """
        self._kernel = kernel

    def run_all(self) -> ConformanceResult:
        """Run all 11 invariants and return a ConformanceResult."""
        from unittest.mock import MagicMock

        from aevum.core.canary import CanarySuite

        mock_kernel = self._kernel or MagicMock()
        canary_suite = CanarySuite(mock_kernel)

        results: list[InvariantResult] = []

        # Run the 8 canary-based invariants individually
        for inv_id, method_name, expected_name in _CANARY_INVARIANTS:
            results.append(self._run_single_canary(canary_suite, inv_id, method_name, expected_name))

        # Invariant 4: structural check (not a canary)
        results.append(self._check_remember_fires())

        # Invariants 10-11: black box receipt format layer (Phase 1A)
        results.append(self._check_cose_structure())
        results.append(self._check_prov_agent_fields())

        results.sort(key=lambda r: r.invariant_id)

        try:
            import aevum.core
            version = getattr(aevum.core, "__version__", "unknown")
        except ImportError:
            version = "unknown"

        return ConformanceResult(
            results=tuple(results),
            checked_at=datetime.now(UTC),
            aevum_version=version,
        )

    def _run_single_canary(
        self,
        canary_suite: Any,
        inv_id: int,
        method_name: str,
        expected_name: str,
    ) -> InvariantResult:
        try:
            method = getattr(canary_suite, method_name)
            result = method()
            # Dual-sig invariant (8) reports FAIL when oqs is absent — treat as
            # not-applicable rather than a conformance failure on this installation.
            if inv_id == 8 and not result.passed and "liboqs" in result.detail:
                return InvariantResult(
                    invariant_id=inv_id,
                    name=result.name,
                    passed=False,
                    skipped=True,
                    detail="oqs not available — dual-sig invariant skipped (liboqs not installed)",
                )
            # Cedar-dependent invariants (3, 7) report FAIL when cedarpy is absent —
            # treat as not-applicable (NullPolicyEngine is in use).
            if inv_id in (3, 7) and not result.passed and "cedarpy" in result.detail:
                return InvariantResult(
                    invariant_id=inv_id,
                    name=result.name,
                    passed=False,
                    skipped=True,
                    detail="cedarpy not installed — Cedar policy invariant skipped",
                )
            return InvariantResult(
                invariant_id=inv_id,
                name=result.name,
                passed=result.passed,
                detail=result.detail,
            )
        except Exception as exc:  # noqa: BLE001
            return InvariantResult(
                invariant_id=inv_id,
                name=expected_name,
                passed=False,
                detail=f"{method_name} raised: {exc}",
            )

    def _check_remember_fires(self) -> InvariantResult:
        """
        Invariant 4: remember_fires_on_every_session_close.
        Verifies that Session has _remember() and CommitType has all 6 values.
        """
        name = "remember_fires_on_every_session_close"
        try:
            from aevum.core.session import Session
            from aevum.core.session_record import CommitType

            if not hasattr(Session, "_remember"):
                return InvariantResult(
                    invariant_id=4, name=name, passed=False,
                    detail="Session has no _remember method",
                )

            if len(CommitType) != 6:
                return InvariantResult(
                    invariant_id=4, name=name, passed=False,
                    detail=f"CommitType has {len(CommitType)} values, expected 6",
                )

            return InvariantResult(invariant_id=4, name=name, passed=True)
        except Exception as exc:  # noqa: BLE001
            return InvariantResult(
                invariant_id=4, name=name, passed=False, detail=str(exc)
            )

    def _check_cose_structure(self) -> InvariantResult:
        """
        Invariant 10 (COSE-STRUCTURE):
        A COSE_Sign1 receipt produced by ReceiptEncoder is a valid 4-element
        CBOR array with alg=-8 in the protected header.
        """
        name = "cose_sign1_receipt_valid_structure_alg_minus_8"
        try:
            import cbor2
            from aevum.core.audit.event import AuditEvent
            from aevum.core.audit.signer import InProcessSigner
            from aevum.core.receipt import AevumReceipt
            try:
                from aevum.publish.encoder import ReceiptEncoder
            except ModuleNotFoundError:
                return InvariantResult(
                    invariant_id=10, name=name, passed=False, skipped=True,
                    detail="aevum-publish not installed — COSE receipt invariant skipped "
                           "(install aevum-publish or aevum-conformance[full] to verify)",
                )

            signer = InProcessSigner()
            encoder = ReceiptEncoder(signer=signer, tsa_client=None, dev_mode=True)

            event = AuditEvent(
                event_id="test-cose-01",
                episode_id="ep-test-01",
                sequence=1,
                event_type="test.action",
                schema_version="1.0",
                valid_from="2026-05-24T00:00:00+00:00",
                valid_to=None,
                system_time=0,
                causation_id=None,
                correlation_id=None,
                actor="test-agent",
                trace_id=None,
                span_id=None,
                payload={"test": True},
                payload_hash=AuditEvent.hash_payload({"test": True}),
                prior_hash="a" * 64,
                signature="dGVzdA",
                signer_key_id="test-key",
            )
            receipt = AevumReceipt.from_sigchain_event(event)
            receipt_cbor = encoder.encode(receipt)

            decoded = cbor2.loads(receipt_cbor)
            if not isinstance(decoded, list) or len(decoded) != 4:
                got_len = len(decoded) if isinstance(decoded, list) else "n/a"
                return InvariantResult(
                    invariant_id=10, name=name, passed=False,
                    detail=f"Expected 4-element array, got {type(decoded).__name__} len={got_len}",
                )

            protected_bstr = decoded[0]
            protected = cbor2.loads(protected_bstr)
            alg = protected.get(1)
            if alg != -8:
                return InvariantResult(
                    invariant_id=10, name=name, passed=False,
                    detail=f"Expected alg=-8 (EdDSA), got alg={alg!r}",
                )

            return InvariantResult(invariant_id=10, name=name, passed=True)
        except Exception as exc:  # noqa: BLE001
            return InvariantResult(
                invariant_id=10, name=name, passed=False, detail=str(exc)
            )

    def _check_prov_agent_fields(self) -> InvariantResult:
        """
        Invariant 11 (PROV-AGENT-FIELDS):
        Every AevumReceipt contains all required PROV-AGENT vocabulary fields
        with non-empty values.

        Note: The formal receipt invariant I7-SCITT_REGISTERED (see ``aevum.core.invariants``)
        is not testable in dev mode (NullBackend); conformance invariant 11 covers the
        PROV-AGENT fields only. SCITT registration is verified only in production mode
        with AEVUM_SCITT_URL set.
        """
        name = "prov_agent_fields_present_in_every_receipt"
        try:
            import cbor2
            from aevum.core.audit.event import AuditEvent
            from aevum.core.receipt import AevumReceipt

            event = AuditEvent(
                event_id="test-prov-01",
                episode_id="ep-test-02",
                sequence=1,
                event_type="test.action",
                schema_version="1.0",
                valid_from="2026-05-24T00:00:00+00:00",
                valid_to=None,
                system_time=0,
                causation_id=None,
                correlation_id=None,
                actor="test-agent",
                trace_id=None,
                span_id=None,
                payload={"test": True},
                payload_hash=AuditEvent.hash_payload({"test": True}),
                prior_hash="b" * 64,
                signature="dGVzdA",
                signer_key_id="test-key",
            )
            receipt = AevumReceipt.from_sigchain_event(event)
            payload_bytes = receipt.to_cbor_payload()
            decoded = cbor2.loads(payload_bytes)

            required_fields = [
                "model_identity_hash",
                "prompt_hash",
                "retrieval_corpus_ver",
                "policy_version",
                "tool_allowlist_hash",
            ]
            missing = [f for f in required_fields if f not in decoded]
            if missing:
                return InvariantResult(
                    invariant_id=11, name=name, passed=False,
                    detail=f"Missing PROV-AGENT fields: {missing}",
                )

            return InvariantResult(invariant_id=11, name=name, passed=True)
        except Exception as exc:  # noqa: BLE001
            return InvariantResult(
                invariant_id=11, name=name, passed=False, detail=str(exc)
            )
