"""Render an OSCAL Component Definition.

This artifact answers "what actually implements this requirement?". A SCuBA
policy says legacy authentication must be blocked; the component definition says
that Microsoft Entra ID is the service responsible and that it is enforced
through tenant configuration. It is the bridge between an abstract control and
the concrete setting an administrator changes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..ids import deterministic_uuid
from ..models import ScubaBaseline
from .common import build_metadata, control_id, prop

#: ScubaGear product abbreviation -> the Microsoft service it assesses.
PRODUCT_NAMES = {
    "AAD": "Microsoft Entra ID",
    "EXO": "Microsoft Exchange Online",
    "DEFENDER": "Microsoft 365 Defender",
    "SHAREPOINT": "Microsoft SharePoint Online",
    "TEAMS": "Microsoft Teams",
    "POWERPLATFORM": "Microsoft Power Platform",
    "POWERBI": "Microsoft Power BI",
}


def build_component_definition(
    baseline: ScubaBaseline,
    *,
    catalog_href: str,
    last_modified: datetime,
    version: str = "1.0.0",
) -> dict[str, Any]:
    """Build an OSCAL component definition for the assessed service."""
    product_name = PRODUCT_NAMES.get(baseline.product.upper(), baseline.product)

    implemented = [
        {
            "uuid": deterministic_uuid("implemented-requirement", p.id),
            "control-id": control_id(p.id),
            "description": (
                f"{product_name} tenant configuration is evaluated against "
                f"{p.id} by CISA ScubaGear. {p.requirement}"
            ),
            "props": [
                prop("scuba-policy-id", p.id),
                prop("criticality", p.criticality),
            ],
        }
        for p in baseline.policies
    ]

    return {
        "component-definition": {
            "uuid": deterministic_uuid(
                "component-definition", baseline.product, version
            ),
            "metadata": build_metadata(
                f"{product_name} - SCuBA control implementation",
                last_modified,
                version=version,
                extra_props=[prop("product", baseline.product)],
            ),
            "components": [
                {
                    "uuid": deterministic_uuid("component", baseline.product),
                    "type": "service",
                    "title": product_name,
                    "description": (
                        f"{product_name} as assessed by CISA ScubaGear against the "
                        f"SCuBA Secure Configuration Baseline."
                    ),
                    "props": [prop("product-abbreviation", baseline.product)],
                    "control-implementations": [
                        {
                            "uuid": deterministic_uuid(
                                "control-implementation", baseline.product
                            ),
                            "source": catalog_href,
                            "description": (
                                "Implementation of the CISA SCuBA Secure "
                                f"Configuration Baseline for {product_name}."
                            ),
                            "implemented-requirements": implemented,
                        }
                    ],
                }
            ],
        }
    }
