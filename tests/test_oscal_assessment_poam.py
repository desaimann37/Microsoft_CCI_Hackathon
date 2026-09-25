"""OSCAL Assessment Results and Plan of Action & Milestones.

These are the runtime artifacts - the ones regenerated every time a tenant is
assessed. Assessment Results restores a distinction ScubaGear flattens away:

  observation  what was queried and what came back  (evidence)
  finding      whether the control is satisfied     (judgement)
  risk         what the failure actually means      (consequence)

The POA&M is the artifact a real user feels immediately: today a human re-types
every failure into a spreadsheet, which puts transcription errors inside an
audit record.
"""

from datetime import datetime, timezone

import pytest

from regulator.models import AnalysisBundle, Remediation, RiskJudgement
from regulator.oscal.assessment_results import build_assessment_results
from regulator.oscal.poam import build_poam
from regulator.parsers.scuba_baseline import parse_baseline
from regulator.parsers.scubagear import parse_assessment
from regulator.validation import validate

FIXED_TIME = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
CATALOG_HREF = "scuba-catalog-aad.json"


@pytest.fixture(scope="module")
def baseline():
    return parse_baseline("data/sources/scuba/aad.md")


@pytest.fixture(scope="module")
def assessment():
    return parse_assessment(
        "data/sources/scubagear/ScubaResults-sample.json", product="AAD"
    )


@pytest.fixture(scope="module")
def analysis(assessment):
    """A stand-in for the AI layer, so the renderers are tested independently."""
    bundle = AnalysisBundle()
    for i, failure in enumerate(assessment.failures):
        bundle.risks.append(
            RiskJudgement(
                policy_id=failure.policy_id,
                severity="high",
                blast_radius="tenant-wide",
                exploitability="remote",
                reasoning="Test judgement.",
                rank=i + 1,
            )
        )
        bundle.remediations.append(
            Remediation(
                policy_id=failure.policy_id,
                steps=("Open the admin centre.", "Change the setting."),
                effort="low",
                owner_role="Identity Administrator",
                target_days=14,
            )
        )
    return bundle


# ---------------------------------------------------------- assessment results


@pytest.fixture(scope="module")
def results(assessment, baseline, analysis):
    return build_assessment_results(
        assessment,
        baseline,
        analysis=analysis,
        catalog_href=CATALOG_HREF,
        last_modified=FIXED_TIME,
    )


def test_assessment_results_are_valid_oscal(results):
    result = validate(results, "assessment-results")
    assert result.valid, [str(e) for e in result.errors[:5]]


def test_records_which_tool_produced_the_evidence(results):
    props = {p["name"]: p["value"] for p in results["assessment-results"]["metadata"]["props"]}
    assert props["assessment-tool"] == "ScubaGear"
    assert props["assessment-tool-version"] == "1.8.0"


def test_records_the_tenant_under_assessment(results):
    props = {p["name"]: p["value"] for p in results["assessment-results"]["metadata"]["props"]}
    assert props["tenant-id"] == "ca08493a-c9c8-4db0-a9e8-d3b4bafac269"


def test_one_observation_per_policy_result(results, assessment):
    obs = results["assessment-results"]["results"][0]["observations"]
    assert len(obs) == len(assessment.results)


def test_findings_are_not_asserted_for_out_of_scope_controls(results, assessment):
    """OSCAL's objective status is strictly satisfied/not-satisfied. A control
    ScubaGear reports as N/A had no judgement made about it, so asserting either
    state would be a lie. Those controls get an observation but no finding."""
    findings = results["assessment-results"]["results"][0]["findings"]
    na = [r for r in assessment.results if r.result == "N/A"]
    assert len(findings) == len(assessment.results) - len(na) == 27


def test_out_of_scope_controls_are_explicitly_excluded(results, assessment):
    """Silence would be ambiguous; OSCAL lets us say 'not reviewed' out loud."""
    selection = results["assessment-results"]["results"][0]["reviewed-controls"][
        "control-selections"
    ][0]
    excluded = {c["control-id"] for c in selection["exclude-controls"]}
    assert len(excluded) == 3
    assert all(
        control_id_of(r) in excluded
        for r in assessment.results
        if r.result == "N/A"
    )


def control_id_of(result):
    from regulator.oscal.common import control_id

    return control_id(result.policy_id)


def test_risks_are_raised_only_for_failures(results, assessment):
    risks = results["assessment-results"]["results"][0]["risks"]
    assert len(risks) == len(assessment.failures) == 11


def test_a_passing_control_is_marked_satisfied(results):
    finding = _finding(results, "MS.AAD.1.1v1")
    assert finding["target"]["status"]["state"] == "satisfied"


def test_a_failing_control_is_marked_not_satisfied(results):
    finding = _finding(results, "MS.AAD.3.1v1")
    assert finding["target"]["status"]["state"] == "not-satisfied"


def test_finding_targets_the_catalog_control(results):
    finding = _finding(results, "MS.AAD.1.1v1")
    assert finding["target"]["target-id"] == "ms.aad.1.1v1"


def test_finding_links_back_to_its_evidence(results):
    """A judgement with no traceable evidence is worthless to an auditor."""
    finding = _finding(results, "MS.AAD.1.1v1")
    assert finding["related-observations"]
    observation_uuids = {
        o["uuid"] for o in results["assessment-results"]["results"][0]["observations"]
    }
    for ref in finding["related-observations"]:
        assert ref["observation-uuid"] in observation_uuids


def test_assessment_results_are_deterministic(assessment, baseline, analysis):
    import json

    kwargs = dict(
        analysis=analysis, catalog_href=CATALOG_HREF, last_modified=FIXED_TIME
    )
    a = json.dumps(build_assessment_results(assessment, baseline, **kwargs), sort_keys=True)
    b = json.dumps(build_assessment_results(assessment, baseline, **kwargs), sort_keys=True)
    assert a == b


# ------------------------------------------------------------------------ poam


@pytest.fixture(scope="module")
def poam(assessment, baseline, analysis, results):
    return build_poam(
        assessment,
        baseline,
        analysis=analysis,
        assessment_results=results,
        last_modified=FIXED_TIME,
    )


def test_poam_is_valid_oscal(poam):
    result = validate(poam, "poam")
    assert result.valid, [str(e) for e in result.errors[:5]]


def test_one_poam_item_per_failure(poam, assessment):
    items = poam["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == len(assessment.failures) == 11


def test_poam_item_carries_remediation_steps(poam):
    item = _poam_item(poam, "MS.AAD.3.1v1")
    assert "Open the admin centre." in item["remarks"]


def test_poam_item_records_effort_and_owner(poam):
    item = _poam_item(poam, "MS.AAD.3.1v1")
    props = {p["name"]: p["value"] for p in item["props"]}
    assert props["remediation-effort"] == "low"
    assert props["suggested-owner"] == "Identity Administrator"


def test_ai_generated_content_is_labelled_as_such(poam):
    """A reviewer must always be able to see what was machine-proposed."""
    item = _poam_item(poam, "MS.AAD.3.1v1")
    props = {p["name"]: p["value"] for p in item["props"]}
    assert props["generated-by"] == "ai-assisted"


def test_poam_items_reference_their_findings(poam):
    item = _poam_item(poam, "MS.AAD.3.1v1")
    assert item["related-findings"]


def test_poam_without_ai_analysis_still_validates(assessment, baseline, results):
    """The deterministic core must never depend on the AI layer being available."""
    bare = build_poam(
        assessment,
        baseline,
        analysis=None,
        assessment_results=results,
        last_modified=FIXED_TIME,
    )
    assert validate(bare, "poam").valid
    assert len(bare["plan-of-action-and-milestones"]["poam-items"]) == 11


def _finding(results, policy_id):
    for f in results["assessment-results"]["results"][0]["findings"]:
        props = {p["name"]: p["value"] for p in f.get("props", [])}
        if props.get("scuba-policy-id") == policy_id:
            return f
    raise AssertionError(f"no finding for {policy_id}")


def _poam_item(poam, policy_id):
    for item in poam["plan-of-action-and-milestones"]["poam-items"]:
        props = {p["name"]: p["value"] for p in item.get("props", [])}
        if props.get("scuba-policy-id") == policy_id:
            return item
    raise AssertionError(f"no POA&M item for {policy_id}")
