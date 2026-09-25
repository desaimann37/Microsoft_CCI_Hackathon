"""Parsing ScubaGear's JSON assessment output.

Run against CISA's own published sample report (ScubaGear v1.8.0), so the parser
is exercised by real tool output including its quirks: a UTF-8 BOM, HTML markup
embedded in the Requirement field, and a 'Criticality' vocabulary that carries
'/Not-Implemented' suffixes.
"""

from datetime import timezone

import pytest

from regulator.parsers.scubagear import parse_assessment

SAMPLE = "data/sources/scubagear/ScubaResults-sample.json"


@pytest.fixture(scope="module")
def assessment():
    return parse_assessment(SAMPLE, product="AAD")


def test_reads_tenant_metadata(assessment):
    assert assessment.tenant_id == "ca08493a-c9c8-4db0-a9e8-d3b4bafac269"
    assert assessment.tenant_name == "tqhjy"


def test_reads_tool_provenance(assessment):
    """An assessment artifact is worthless without knowing what produced it."""
    assert assessment.tool == "ScubaGear"
    assert assessment.tool_version == "1.8.0"


def test_reads_an_aware_utc_timestamp(assessment):
    assert assessment.timestamp.tzinfo is not None
    assert assessment.timestamp.astimezone(timezone.utc).year == 2026


def test_reads_every_aad_result(assessment):
    """The sample contains 30 Entra ID policy results."""
    assert len(assessment.results) == 30


def test_counts_match_scubagears_own_summary(assessment):
    """ScubaGear publishes its own tallies in Summary.AAD; ours must agree."""
    counts = {}
    for r in assessment.results:
        counts[r.result] = counts.get(r.result, 0) + 1
    assert counts == {"Pass": 12, "Fail": 11, "Warning": 4, "N/A": 3}


def test_exposes_failures_directly(assessment):
    assert len(assessment.failures) == 11
    assert all(r.result == "Fail" for r in assessment.failures)


def test_reads_a_passing_result(assessment):
    r = assessment.result("MS.AAD.1.1v1")
    assert r.result == "Pass"
    assert r.group_number == "1"
    assert r.group_name == "Legacy Authentication"


def test_reads_a_failing_result(assessment):
    r = assessment.result("MS.AAD.3.1v1")
    assert r.result == "Fail"
    assert r.is_failure is True


def test_details_are_carried_through(assessment):
    """Details become the OSCAL observation description, so they must survive."""
    r = assessment.result("MS.AAD.1.1v1")
    assert "conditional access policy" in r.details.lower()


def test_html_markup_is_stripped_from_details(assessment):
    """ScubaGear embeds <br/> and anchor tags in its detail text."""
    for r in assessment.results:
        assert "<" not in r.details


def test_product_filter_excludes_other_products(assessment):
    """The sample also contains Defender, EXO, SharePoint, Teams results."""
    assert all(r.policy_id.startswith("MS.AAD.") for r in assessment.results)


def test_a_different_product_parses_too():
    """The parser must not be hardcoded to Entra ID."""
    exo = parse_assessment(SAMPLE, product="EXO")
    assert len(exo.results) > 0
    assert all(r.policy_id.startswith("MS.EXO.") for r in exo.results)


def test_unknown_product_raises():
    with pytest.raises(KeyError):
        parse_assessment(SAMPLE, product="NOPE")


def test_unknown_policy_raises(assessment):
    with pytest.raises(KeyError):
        assessment.result("MS.AAD.99.9v1")
