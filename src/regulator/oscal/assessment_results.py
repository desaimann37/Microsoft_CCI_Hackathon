"""Render ScubaGear results as OSCAL Assessment Results.

ScubaGear reports a single Pass/Fail column. OSCAL asks for three distinct
things, and separating them is genuine analytical value rather than reformatting:

    observation   what was queried and what came back   (evidence)
    finding       whether the control is satisfied      (judgement)
    risk          what the failure actually means       (consequence)

Risks are raised only for failures, and carry the AI layer's severity judgement
when one is available. The renderer works without the AI layer - the
deterministic core never depends on a model being reachable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..ids import deterministic_uuid
from ..models import AnalysisBundle, Assessment, ScubaBaseline
from .common import build_metadata, control_id, oscal_timestamp, prop

#: ScubaGear verdict -> OSCAL objective status state.
STATUS_MAP = {
    "Pass": "satisfied",
    "Fail": "not-satisfied",
    # A warning means the automated check could not fully confirm compliance;
    # claiming "satisfied" would overstate the evidence.
    "Warning": "not-satisfied",
}

#: ScubaGear verdicts for which no compliance judgement was made. OSCAL's
#: objective status admits only satisfied/not-satisfied, so asserting either
#: would misstate the evidence. These are recorded as observations and named in
#: the result's exclude-controls instead.
NO_JUDGEMENT = {"N/A"}


def build_assessment_results(
    assessment: Assessment,
    baseline: ScubaBaseline,
    *,
    catalog_href: str,
    last_modified: datetime,
    analysis: AnalysisBundle | None = None,
    version: str = "1.0.0",
) -> dict[str, Any]:
    """Build an OSCAL assessment-results document from a ScubaGear run."""
    run_key = f"{assessment.tenant_id}:{assessment.timestamp.isoformat()}"

    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []

    for res in assessment.results:
        obs_uuid = deterministic_uuid("observation", run_key, res.policy_id)
        observations.append(
            {
                "uuid": obs_uuid,
                "title": f"{res.policy_id} configuration queried",
                "description": (
                    res.details
                    or f"ScubaGear evaluated {res.policy_id} against the tenant."
                ),
                "methods": ["TEST"],
                "props": [
                    prop("scuba-policy-id", res.policy_id),
                    prop("scubagear-result", res.result),
                ],
                "collected": oscal_timestamp(assessment.timestamp),
            }
        )

        if res.result in NO_JUDGEMENT:
            continue

        state = STATUS_MAP.get(res.result, "not-satisfied")
        findings.append(
            {
                "uuid": deterministic_uuid("finding", run_key, res.policy_id),
                "title": f"{res.policy_id} {state.replace('-', ' ')}",
                "description": (
                    f"ScubaGear reported '{res.result}' for {res.policy_id}. "
                    f"{res.details}".strip()
                ),
                "props": [
                    prop("scuba-policy-id", res.policy_id),
                    prop("baseline-section", res.group_number),
                ],
                "target": {
                    "type": "objective-id",
                    "target-id": control_id(res.policy_id),
                    "status": {"state": state},
                },
                "related-observations": [{"observation-uuid": obs_uuid}],
            }
        )

        if res.is_failure:
            risks.append(_risk(res, baseline, run_key, analysis))

    return {
        "assessment-results": {
            "uuid": deterministic_uuid("assessment-results", run_key),
            "metadata": build_metadata(
                f"SCuBA assessment - {assessment.tenant_name} ({assessment.product})",
                last_modified,
                version=version,
                extra_props=[
                    prop("tenant-id", assessment.tenant_id),
                    prop("tenant-name", assessment.tenant_name),
                    prop("product", assessment.product),
                    prop("assessment-tool", assessment.tool),
                    prop("assessment-tool-version", assessment.tool_version),
                ],
            ),
            # OSCAL requires assessment results to cite the plan they execute.
            # ScubaGear is itself the plan: its Rego policies define the method.
            "import-ap": {"href": catalog_href},
            "results": [
                {
                    "uuid": deterministic_uuid("result", run_key),
                    "title": f"ScubaGear {assessment.product} assessment",
                    "description": (
                        f"Automated assessment of tenant {assessment.tenant_name} "
                        f"against the CISA SCuBA {assessment.product} baseline, "
                        f"performed by {assessment.tool} {assessment.tool_version}."
                    ),
                    "start": oscal_timestamp(assessment.timestamp),
                    "reviewed-controls": {
                        "control-selections": [
                            _control_selection(assessment),
                        ]
                    },
                    "observations": observations,
                    "risks": risks,
                    "findings": findings,
                }
            ],
        }
    }


def _control_selection(assessment: Assessment) -> dict[str, Any]:
    """Name what was reviewed, and say out loud what was not.

    Leaving out-of-scope controls silently absent would be ambiguous: a reader
    could not tell "not applicable" from "we forgot".
    """
    selection: dict[str, Any] = {
        "include-controls": [
            {"control-id": control_id(r.policy_id)}
            for r in assessment.results
            if r.result not in NO_JUDGEMENT
        ]
    }
    excluded = [
        {"control-id": control_id(r.policy_id)}
        for r in assessment.results
        if r.result in NO_JUDGEMENT
    ]
    if excluded:
        selection["exclude-controls"] = excluded
    return selection


def _risk(res, baseline: ScubaBaseline, run_key: str, analysis) -> dict[str, Any]:
    """Build the risk raised by one failed control."""
    try:
        policy = baseline.policy(res.policy_id)
        requirement = policy.requirement
        rationale = policy.rationale or ""
    except KeyError:
        # Version skew: the tenant was assessed with a ScubaGear build whose
        # policy set differs from the baseline we parsed. Surface it, never
        # silently drop it.
        requirement = res.details
        rationale = ""

    judgement = analysis.risk_for(res.policy_id) if analysis else None
    props = [prop("scuba-policy-id", res.policy_id)]
    if judgement:
        props += [
            prop("severity", judgement.severity),
            prop("blast-radius", judgement.blast_radius),
            prop("exploitability", judgement.exploitability),
            prop("priority-rank", str(judgement.rank)),
            prop("generated-by", "ai-assisted"),
        ]

    statement = rationale or f"The tenant does not satisfy {res.policy_id}."
    if judgement:
        statement = f"{statement} {judgement.reasoning}".strip()

    return {
        "uuid": deterministic_uuid("risk", run_key, res.policy_id),
        "title": f"{res.policy_id} not satisfied: {requirement}",
        "description": res.details or requirement,
        "statement": statement,
        "props": props,
        "status": "open",
    }
