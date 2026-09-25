"""Measuring crosswalk quality against CISA's own published mapping.

Nearly every hackathon entry will *assert* that its AI works. This module makes
it possible to show a number instead. The ground truth is not hand-laboured by
us - CISA authored a NIST SP 800-53 mapping for each SCuBA policy and published
it inside the baseline, so the reference set is authoritative and covers every
policy rather than a sample of thirty.

Two scores are reported, deliberately:

exact
    the predicted control ID equals CISA's. Strict, and arguably too strict -
    proposing ia-2 where CISA wrote ia-2(1) scores zero.
family
    the predicted control is in the same 800-53 family. Partial credit for a
    near miss, which is what a human reviewer would call "basically right".

Reporting only the flattering one would be dishonest, so both are always shown.
"""

import pytest

from regulator.agents.crosswalk import CrosswalkEngine
from regulator.agents.heuristic import HeuristicProvider
from regulator.evaluation import Score, evaluate_crosswalk, score_sets
from regulator.nist_catalog import NistCatalog
from regulator.parsers.scuba_baseline import parse_baseline


@pytest.fixture(scope="module")
def catalog():
    return NistCatalog.load("data/sources/nist/sp800-53r5-catalog.json")


@pytest.fixture(scope="module")
def baseline():
    return parse_baseline("data/sources/scuba/aad.md")


# ------------------------------------------------------------------- metrics


def test_perfect_prediction_scores_one():
    s = score_sets(predicted={"ia-2.1", "cm-7"}, truth={"ia-2.1", "cm-7"})
    assert s.precision == 1.0
    assert s.recall == 1.0
    assert s.f1 == 1.0


def test_completely_wrong_prediction_scores_zero():
    s = score_sets(predicted={"au-1"}, truth={"cm-7"})
    assert s.precision == 0.0
    assert s.recall == 0.0
    assert s.f1 == 0.0


def test_partial_prediction_scores_between():
    """Predicted two, one right, truth had one: precision 0.5, recall 1.0."""
    s = score_sets(predicted={"cm-7", "au-1"}, truth={"cm-7"})
    assert s.precision == 0.5
    assert s.recall == 1.0
    assert round(s.f1, 3) == 0.667


def test_empty_prediction_is_not_a_division_error():
    s = score_sets(predicted=set(), truth={"cm-7"})
    assert s.precision == 0.0
    assert s.recall == 0.0
    assert s.f1 == 0.0


def test_empty_truth_is_not_a_division_error():
    s = score_sets(predicted={"cm-7"}, truth=set())
    assert s.f1 == 0.0


# ---------------------------------------------------------------- evaluation


@pytest.fixture(scope="module")
def report(catalog, baseline):
    engine = CrosswalkEngine(catalog, HeuristicProvider(catalog))
    return evaluate_crosswalk(engine, baseline)


def test_report_covers_policies_that_have_ground_truth(report, baseline):
    with_truth = [p for p in baseline.policies if p.nist_controls]
    assert report.policies_evaluated == len(with_truth)
    assert report.policies_evaluated > 20


def test_report_produces_both_exact_and_family_scores(report):
    assert isinstance(report.exact, Score)
    assert isinstance(report.family, Score)


def test_family_score_is_at_least_the_exact_score(report):
    """Family matching is strictly more forgiving, so it cannot score lower."""
    assert report.family.recall >= report.exact.recall


def test_all_scores_are_probabilities(report):
    for s in (report.exact, report.family):
        assert 0.0 <= s.precision <= 1.0
        assert 0.0 <= s.recall <= 1.0
        assert 0.0 <= s.f1 <= 1.0


def test_report_keeps_per_policy_detail(report):
    """An aggregate number with no drill-down cannot be acted on."""
    assert report.per_policy
    row = report.per_policy[0]
    assert row.policy_id.startswith("MS.AAD.")
    assert isinstance(row.predicted, list)
    assert isinstance(row.truth, list)


def test_report_records_the_provider_it_measured(report):
    assert "Heuristic" in report.provider


def test_report_serialises_for_the_dashboard(report):
    data = report.to_dict()
    assert data["exact"]["f1"] == report.exact.f1
    assert len(data["per_policy"]) == report.policies_evaluated


def test_hit_rate_counts_policies_with_at_least_one_correct_mapping(report):
    """The number a reviewer actually cares about: did it find *anything* right?"""
    assert 0.0 <= report.exact_hit_rate <= 1.0
    assert 0.0 <= report.family_hit_rate <= 1.0
    assert report.family_hit_rate >= report.exact_hit_rate
