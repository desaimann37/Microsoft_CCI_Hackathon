"""Render a SCuBA baseline as an OSCAL Catalog.

The catalog turns CISA's prose baseline into addressable control objects. Each
SCuBA policy becomes one OSCAL control; each numbered baseline section becomes
one group.

CISA's own SP 800-53 mapping is carried through as OSCAL links tagged
``source=cisa``. This matters: those links are authoritative, hand-authored
content, and they must never be confused with the AI-derived mappings the
crosswalk agent adds later, which are tagged ``source=ai``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..ids import deterministic_uuid
from ..models import ScubaBaseline
from .common import (
    build_metadata,
    control_id,
    link,
    nist_control_id,
    part,
    prop,
    scuba_source_resource,
)

BASELINE_URL_TEMPLATE = (
    "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/{}.md"
)


def build_catalog(
    baseline: ScubaBaseline, *, last_modified: datetime, version: str = "1.0.0"
) -> dict[str, Any]:
    """Build an OSCAL catalog document from a parsed SCuBA baseline."""
    source_url = BASELINE_URL_TEMPLATE.format(baseline.product.lower())

    groups = []
    for group in baseline.groups:
        controls = [
            _control(policy, source_url)
            for policy in baseline.policies
            if policy.group_number == group.number
        ]
        if not controls:
            # OSCAL forbids an empty controls array (minItems: 1).
            continue
        groups.append(
            {
                "id": f"{baseline.product.lower()}-{group.number}",
                "title": group.name,
                "controls": controls,
            }
        )

    return {
        "catalog": {
            "uuid": deterministic_uuid("catalog", baseline.product, version),
            "metadata": build_metadata(
                baseline.title or f"CISA SCuBA Baseline - {baseline.product}",
                last_modified,
                version=version,
                extra_props=[
                    prop("source-framework", "CISA SCuBA"),
                    prop("product", baseline.product),
                ],
            ),
            "groups": groups,
            "back-matter": {
                "resources": [
                    scuba_source_resource(
                        source_url,
                        f"CISA SCuBA Secure Configuration Baseline - {baseline.product}",
                    )
                ]
            },
        }
    }


def _control(policy, source_url: str) -> dict[str, Any]:
    props = [
        prop("scuba-policy-id", policy.id),
        prop("criticality", policy.criticality),
        prop("baseline-section", policy.group_number),
    ]
    if policy.bod_25_01:
        props.append(prop("bod-25-01", "required"))
    if policy.last_modified:
        props.append(prop("policy-last-modified", policy.last_modified))
    for technique in policy.mitre_techniques:
        props.append(prop("mitre-attack-technique", technique))

    parts = [part("statement", policy.requirement)]
    if policy.rationale:
        parts.append(part("guidance", policy.rationale))

    links = [link(source_url, "reference", "CISA SCuBA baseline")]
    # CISA's published mapping - authoritative, and the crosswalk agent's
    # ground truth. Tagged so AI-derived links stay distinguishable.
    for control in policy.nist_controls:
        links.append(
            link(
                f"#{nist_control_id(control)}",
                "related",
                f"NIST SP 800-53 Rev 5 {control} (CISA mapping)",
            )
        )

    return {
        "id": control_id(policy.id),
        "title": policy.requirement,
        "props": props,
        "links": links,
        "parts": parts,
    }
