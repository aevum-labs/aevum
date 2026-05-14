# SPDX-License-Identifier: Apache-2.0
import math
import pytest
from aevum.core.functions.query import compute_edge_score


class TestThreeAxisDecay:
    """Test the 3-axis relevance scoring formula."""

    def test_score_in_zero_to_one_range(self):
        score = compute_edge_score(1.0, 2.0, 100.0)
        assert 0.0 <= score <= 1.0

    def test_closer_distance_scores_higher(self):
        near = compute_edge_score(1.0, 2.0, 100.0)
        far = compute_edge_score(5.0, 2.0, 100.0)
        assert near > far, "Closer nodes must score higher"

    def test_lower_complexity_scores_higher(self):
        simple = compute_edge_score(1.0, 1.0, 100.0)
        complex_ = compute_edge_score(1.0, 50.0, 100.0)
        assert simple > complex_, "Simpler (focused) nodes must score higher"

    def test_larger_size_scores_higher_than_tiny(self):
        medium = compute_edge_score(1.0, 2.0, 500.0)
        tiny = compute_edge_score(1.0, 2.0, 1.0)
        assert medium > tiny, "Medium content must outscore empty/tiny"

    def test_zero_size_does_not_raise(self):
        score = compute_edge_score(1.0, 1.0, 0.0)
        assert 0.0 <= score <= 1.0

    def test_very_far_node_approaches_zero(self):
        score = compute_edge_score(100.0, 100.0, 1.0)
        assert score < 0.01, "Very distant, complex, tiny node must approach 0"

    def test_ideal_node_approaches_high_score(self):
        score = compute_edge_score(1.0, 1.0, 1000.0)
        assert score > 0.2, "Close, simple, medium-sized node must score reasonably high"

    def test_distance_decay_is_exponential(self):
        s1 = compute_edge_score(1.0, 1.0, 100.0)
        s2 = compute_edge_score(2.0, 1.0, 100.0)
        s3 = compute_edge_score(3.0, 1.0, 100.0)
        # Each additional hop reduces the score
        assert s1 > s2 > s3

    def test_custom_lambda_d(self):
        slow_decay = compute_edge_score(5.0, 1.0, 100.0, lambda_d=0.1)
        fast_decay = compute_edge_score(5.0, 1.0, 100.0, lambda_d=0.9)
        assert slow_decay > fast_decay

    def test_score_never_exceeds_one(self):
        score = compute_edge_score(0.0001, 0.0001, 10_000.0)
        assert score <= 1.0

    def test_score_never_below_zero(self):
        score = compute_edge_score(1000.0, 1000.0, 0.0)
        assert score >= 0.0

    def test_d_score_component(self):
        # d_score = exp(-lambda_d * distance)
        score = compute_edge_score(0.0, 0.0, 0.0, lambda_d=0.3)
        # When distance=0: d_score=1, c_score=1/(1+0)=1, s_score=log(1)/log(10001)=0
        assert score == pytest.approx(0.0)

    def test_complexity_zero_does_not_raise(self):
        score = compute_edge_score(1.0, 0.0, 100.0)
        assert 0.0 <= score <= 1.0

    def test_high_complexity_suppresses_score(self):
        low_c = compute_edge_score(1.0, 1.0, 100.0)
        high_c = compute_edge_score(1.0, 1000.0, 100.0)
        assert low_c > high_c

    def test_size_log_scaling(self):
        s1 = compute_edge_score(1.0, 1.0, 100.0)
        s2 = compute_edge_score(1.0, 1.0, 1000.0)
        s3 = compute_edge_score(1.0, 1.0, 10_000.0)
        # Larger content scores higher (up to ~10_000 chars normalization)
        assert s1 < s2 < s3
