# SPDX-License-Identifier: Apache-2.0
import dataclasses
import json
from datetime import datetime

import pytest

from aevum.conformance.suite import ConformanceResult, ConformanceSuite, InvariantResult


class TestConformanceSuite:
    def test_run_all_returns_result(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        assert isinstance(result, ConformanceResult)

    def test_nine_invariants_returned(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        assert result.total_count >= 9  # expanded to 11 in Phase 1A

    def test_all_invariants_pass_on_correct_installation(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        failures = [r for r in result.results if not r.passed]
        assert not failures, [f"{r.invariant_id}: {r.name}: {r.detail}" for r in failures]

    def test_result_has_timestamp(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        assert isinstance(result.checked_at, datetime)

    def test_render_contains_pass_or_fail(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        rendered = result.render()
        assert "PASS" in rendered or "FAIL" in rendered

    def test_render_contains_all_nine_invariant_ids(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        rendered = result.render()
        for i in range(1, 10):
            assert str(i) in rendered

    def test_to_dict_is_json_serializable(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        d = result.to_dict()
        json.dumps(d)  # must not raise

    def test_all_passed_is_bool(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        assert isinstance(result.all_passed, bool)

    def test_invariant_ids_one_through_nine(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        ids = {r.invariant_id for r in result.results}
        assert set(range(1, 10)).issubset(ids)  # 1-9 always present; suite expanded in Phase 1A

    def test_passed_count_matches(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        assert result.passed_count == sum(1 for r in result.results if r.passed)

    def test_render_contains_header(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        rendered = result.render()
        assert "AEVUM CONFORMANCE REPORT" in rendered

    def test_render_contains_version_line(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        rendered = result.render()
        assert "Version:" in rendered

    def test_to_dict_has_required_keys(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        d = result.to_dict()
        for key in ("checked_at", "aevum_version", "passed", "passed_count", "total_count", "results"):
            assert key in d

    def test_to_dict_results_have_required_fields(self) -> None:
        suite = ConformanceSuite()
        result = suite.run_all()
        d = result.to_dict()
        for entry in d["results"]:
            for field in ("invariant_id", "name", "passed", "detail"):
                assert field in entry


class TestInvariantResult:
    def test_frozen(self) -> None:
        r = InvariantResult(1, "test", True)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            r.passed = False  # type: ignore[misc]

    def test_default_detail_empty(self) -> None:
        r = InvariantResult(1, "test", True)
        assert r.detail == ""

    def test_custom_detail(self) -> None:
        r = InvariantResult(2, "test2", False, detail="something failed")
        assert r.detail == "something failed"


class TestConformanceResult:
    def test_all_passed_true_when_all_pass(self) -> None:
        results = tuple(InvariantResult(i, f"inv{i}", True) for i in range(1, 10))
        cr = ConformanceResult(results=results, checked_at=datetime.now(), aevum_version="test")
        assert cr.all_passed is True

    def test_all_passed_false_when_one_fails(self) -> None:
        results = tuple(InvariantResult(i, f"inv{i}", i != 3) for i in range(1, 10))
        cr = ConformanceResult(results=results, checked_at=datetime.now(), aevum_version="test")
        assert cr.all_passed is False

    def test_passed_count(self) -> None:
        results = tuple(InvariantResult(i, f"inv{i}", i <= 7) for i in range(1, 10))
        cr = ConformanceResult(results=results, checked_at=datetime.now(), aevum_version="test")
        assert cr.passed_count == 7

    def test_total_count(self) -> None:
        results = tuple(InvariantResult(i, f"inv{i}", True) for i in range(1, 10))
        cr = ConformanceResult(results=results, checked_at=datetime.now(), aevum_version="test")
        assert cr.total_count == 9
