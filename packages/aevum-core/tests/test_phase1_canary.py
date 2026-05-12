# SPDX-License-Identifier: Apache-2.0
from unittest.mock import MagicMock, patch

import pytest

from aevum.core.canary import CanaryError, CanaryResult, CanarySuite


class TestCanarySuite:
    def _make_suite(self) -> CanarySuite:
        kernel = MagicMock()
        return CanarySuite(kernel)

    def test_run_all_passes_on_valid_setup(self):
        suite = self._make_suite()
        results = suite.run_all()
        assert isinstance(results, list)
        assert all(isinstance(r, CanaryResult) for r in results)
        assert all(r.passed for r in results)

    def test_run_all_returns_six_results(self):
        suite = self._make_suite()
        results = suite.run_all()
        assert len(results) == 6

    def test_all_canary_names_are_unique(self):
        suite = self._make_suite()
        results = suite.run_all()
        names = [r.name for r in results]
        assert len(names) == len(set(names))

    def test_dual_sig_canary_exercises_liboqs(self):
        suite = self._make_suite()
        results = suite.run_all()
        dual_sig_result = next(
            r for r in results if "dual_signature" in r.name
        )
        assert dual_sig_result.passed

    def test_canary_error_raised_if_signing_broken(self):
        """Simulate a broken signing module."""
        suite = self._make_suite()
        # Patch DualSigner.generate to raise — requires module-level import in canary.py
        with patch(
            "aevum.core.canary.DualSigner.generate",
            side_effect=RuntimeError("signing broken"),
        ), pytest.raises(CanaryError, match="dual_signature"):
            suite.run_all()

    def test_canary_result_has_name_and_passed(self):
        suite = self._make_suite()
        results = suite.run_all()
        for r in results:
            assert hasattr(r, "name")
            assert hasattr(r, "passed")
            assert isinstance(r.name, str)
            assert isinstance(r.passed, bool)

    def test_crisis_barrier_canary_passes(self):
        suite = self._make_suite()
        results = suite.run_all()
        crisis = next(r for r in results if "crisis_barrier" in r.name)
        assert crisis.passed

    def test_consent_canary_passes(self):
        suite = self._make_suite()
        results = suite.run_all()
        consent = next(r for r in results if "consent" in r.name.lower())
        assert consent.passed

    def test_audit_chain_canary_passes(self):
        suite = self._make_suite()
        results = suite.run_all()
        audit = next(r for r in results if "audit_chain" in r.name)
        assert audit.passed

    def test_run_all_clears_previous_results(self):
        suite = self._make_suite()
        suite.run_all()
        results2 = suite.run_all()
        assert len(results2) == 6  # not 12

    def test_canary_error_message_contains_name(self):
        suite = self._make_suite()
        with patch(
            "aevum.core.canary.DualSigner.generate",
            side_effect=RuntimeError("broken"),
        ):
            with pytest.raises(CanaryError) as exc_info:
                suite.run_all()
            assert "dual_signature" in str(exc_info.value)
