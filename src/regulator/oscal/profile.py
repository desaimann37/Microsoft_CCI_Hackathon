"""Render an OSCAL Profile - a selection of controls from the catalog.

A profile is OSCAL's word for a baseline: it imports a catalog and states which
of its controls apply. The challenge brief asks entrants to "select a meaningful
subset" of the SCuBA baselines; a profile is the standard's own way of saying
exactly that, which is why the subset is expressed here rather than as an ad-hoc
filter somewhere in application code.

Two selections are supported:
  * the full product baseline, and
  * the subset CISA marks as mandatory under BOD 25-01, which is the set
    agencies are actually ordered to implement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..ids import deterministic_uuid
from ..models import ScubaBaseline
from .common import build_metadata, control_id, prop


def build_profile(
    baseline: ScubaBaseline,
    *,
    catalog_href: str,
    last_modified: datetime,
    only_bod_25_01: bool = False,
    version: str = "1.0.0",
) -> dict[str, Any]:
    """Build an OSCAL profile selecting controls from the SCuBA catalog."""
    policies = [
        p for p in baseline.policies if (p.bod_25_01 if only_bod_25_01 else True)
    ]
    selection = "bod-25-01" if only_bod_25_01 else "full"

    title = (
        f"CISA SCuBA {baseline.product} - BOD 25-01 mandatory policies"
        if only_bod_25_01
        else f"CISA SCuBA {baseline.product} - full baseline"
    )

    return {
        "profile": {
            "uuid": deterministic_uuid("profile", baseline.product, selection, version),
            "metadata": build_metadata(
                title,
                last_modified,
                version=version,
                extra_props=[
                    prop("product", baseline.product),
                    prop("selection", selection),
                ],
            ),
            "imports": [
                {
                    "href": catalog_href,
                    "include-controls": [
                        {"with-ids": [control_id(p.id) for p in policies]}
                    ],
                }
            ],
            "merge": {"as-is": True},
        }
    }
