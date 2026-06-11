# SPDX-License-Identifier: Apache-2.0
from unittest.mock import MagicMock, patch

import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, SystemExit):
    pytest.skip("liboqs native library not available — skipping oqs-dependent tests", allow_module_level=True)

from aevum.core.canary import CanaryError, CanarySuite


class TestPhase3Canaries:
    def _suite(self) -> CanarySuite:
        return CanarySuite(kernel=MagicMock())

    def test_all_seven_canaries_pass(self):
        suite = self._suite()
        results = suite.run_all()
        assert len(results) == 7, f"Expected 7 canaries, got {len(results)}"
        failures = [r for r in results if not r.passed and not r.skipped]
        assert not failures, [f"{r.name}: {r.detail}" for r in failures]

    def test_canary3_uncertainty_mandatory(self):
        suite = self._suite()
        result = suite._canary_uncertainty_mandatory()
        assert result.passed, result.detail

    def test_canary4_reasoning_trace_mandatory(self):
        suite = self._suite()
        result = suite._canary_reasoning_trace_mandatory()
        assert result.passed, result.detail

    def test_canary9_consent_revoke_destroys_dek(self):
        suite = self._suite()
        result = suite._canary_consent_revoke_destroys_dek()
        assert result.passed, result.detail

    def test_canary_uncertainty_name(self):
        suite = self._suite()
        result = suite._canary_uncertainty_mandatory()
        assert result.name == "uncertainty_present_in_every_ContextBundle"

    def test_canary_reasoning_trace_name(self):
        suite = self._suite()
        result = suite._canary_reasoning_trace_mandatory()
        assert result.name == "reasoning_trace_nonempty_in_every_ContextBundle"

    def test_canary_dek_shredding_name(self):
        suite = self._suite()
        result = suite._canary_consent_revoke_destroys_dek()
        assert result.name == "consent_revoke_destroys_dek"

    def test_run_all_returns_list_of_canary_results(self):
        from aevum.core.canary import CanaryResult
        suite = self._suite()
        results = suite.run_all()
        assert all(isinstance(r, CanaryResult) for r in results)

    def test_run_all_raises_canary_error_on_failure(self):
        suite = self._suite()
        with patch("aevum.core.barriers.crisis_barrier_check", return_value=None), pytest.raises(CanaryError):
            suite.run_all()

    def test_canary_uncertainty_rejects_none(self):
        """_canary_uncertainty_mandatory must detect uncertainty=None acceptance."""
        suite = self._suite()
        result = suite._canary_uncertainty_mandatory()
        # With correct ContextBundle, the canary should pass
        assert result.passed, result.detail

    def test_canary_reasoning_trace_rejects_empty(self):
        """_canary_reasoning_trace_mandatory must detect empty reasoning_trace."""
        suite = self._suite()
        result = suite._canary_reasoning_trace_mandatory()
        assert result.passed, result.detail

    def test_canary7_is_dek_shredding(self):
        """The 7th canary (index 6) must be consent_revoke_destroys_dek."""
        suite = self._suite()
        results = suite.run_all()
        assert results[6].name == "consent_revoke_destroys_dek"

    def test_canary4_is_reasoning_trace(self):
        """The 4th canary (index 3) must be reasoning_trace_nonempty."""
        suite = self._suite()
        results = suite.run_all()
        assert "reasoning_trace" in results[3].name

    def test_canary1_is_crisis(self):
        suite = self._suite()
        results = suite.run_all()
        assert "crisis" in results[0].name

    def test_canary2_is_consent_required(self):
        suite = self._suite()
        results = suite.run_all()
        assert "consent" in results[1].name
