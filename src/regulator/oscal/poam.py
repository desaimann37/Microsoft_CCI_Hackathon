"""Render a Plan of Action & Milestones from failed findings.

This is the artifact a real user feels immediately. Today, every failed check is
read off an HTML report and re-typed into a spreadsheet by hand - which puts
transcription errors inside a record auditors read closely. Here it is generated
directly from the same data that produced the findings, with the AI layer
supplying remediation steps, effort and ownership.

Anything the model contributed is labelled ``generated-by: ai-assisted`` so a
reviewer can always see what was machine-proposed. The renderer degrades
cleanly when no AI analysis is available.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from ..ids import deterministic_uuid
from ..models import AnalysisBundle, Assessment, ScubaBaseline
from .common import build_metadata, prop

#: Fallback remediation windows when the AI layer is unavailable, by criticality.
DEFAULT_TARGET_DAYS = {"SHALL": 30, "SHOULD": 90}


def build_poam(
    assessment: Assessment,
    baseline: ScubaBaseline,
    *,
    assessment_results: dict[str, Any],
    last_modified: datetime,
    analysis: AnalysisBundle | None = None,
    version: str = "1.0.0",
) -> dict[str, Any]:
    """Build an OSCAL POA&M from the failures in an assessment."""
    run_key = f"{assessment.tenant_id}:{assessment.timestamp.isoformat()}"

    finding_uuids = {
        p["value"]: f["uuid"]
        for result in assessment_results["assessment-results"]["results"]
        for f in result["findings"]
        for p in f.get("props", [])
        if p["name"] == "scuba-policy-id"
    }
    risk_uuids = {
        p["value"]: r["uuid"]
        for result in assessment_results["assessment-results"]["results"]
        for r in result.get("risks", [])
        for p in r.get("props", [])
        if p["name"] == "scuba-policy-id"
    }

    items = [
        _item(res, baseline, run_key, analysis, finding_uuids, risk_uuids, last_modified)
        for res in assessment.failures
    ]

    return {
        "plan-of-action-and-milestones": {
            "uuid": deterministic_uuid("poam", run_key),
            "metadata": build_metadata(
                f"POA&M - {assessment.tenant_name} ({assessment.product})",
                last_modified,
                version=version,
                extra_props=[
                    prop("tenant-id", assessment.tenant_id),
                    prop("product", assessment.product),
                    prop("open-items", str(len(items))),
                ],
            ),
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": assessment.tenant_id,
            },
            "poam-items": items,
        }
    }


def _item(
    res,
    baseline: ScubaBaseline,
    run_key: str,
    analysis: AnalysisBundle | None,
    finding_uuids: dict[str, str],
    risk_uuids: dict[str, str],
    last_modified: datetime,
) -> dict[str, Any]:
    try:
        policy = baseline.policy(res.policy_id)
        requirement = policy.requirement
        criticality = policy.criticality
    except KeyError:
        requirement = res.details
        criticality = "SHALL"

    remediation = analysis.remediation_for(res.policy_id) if analysis else None
    judgement = analysis.risk_for(res.policy_id) if analysis else None

    target_days = (
        remediation.target_days
        if remediation
        else DEFAULT_TARGET_DAYS.get(criticality, 30)
    )
    target_date = (last_modified + timedelta(days=target_days)).date().isoformat()

    props = [
        prop("scuba-policy-id", res.policy_id),
        prop("criticality", criticality),
        prop("target-date", target_date),
    ]
    if judgement:
        props += [
            prop("severity", judgement.severity),
            prop("priority-rank", str(judgement.rank)),
        ]
    if remediation:
        props += [
            prop("remediation-effort", remediation.effort),
            prop("suggested-owner", remediation.owner_role),
            prop("generated-by", "ai-assisted"),
        ]

    if remediation and remediation.steps:
        remarks = "Remediation steps:\n" + "\n".join(
            f"{i}. {s}" for i, s in enumerate(remediation.steps, 1)
        )
    else:
        remarks = (
            "No automated remediation guidance available. "
            "Consult the CISA SCuBA implementation guidance for this policy."
        )

    item: dict[str, Any] = {
        "uuid": deterministic_uuid("poam-item", run_key, res.policy_id),
        "title": f"{res.policy_id}: {requirement}",
        "description": (
            f"ScubaGear reported '{res.result}' for {res.policy_id}. {res.details}"
        ).strip(),
        "props": props,
        "remarks": remarks,
    }

    if res.policy_id in finding_uuids:
        item["related-findings"] = [{"finding-uuid": finding_uuids[res.policy_id]}]
    if res.policy_id in risk_uuids:
        item["related-risks"] = [{"risk-uuid": risk_uuids[res.policy_id]}]

    return item
