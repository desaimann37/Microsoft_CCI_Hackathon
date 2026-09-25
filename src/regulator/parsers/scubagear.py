"""Parse ScubaGear's JSON assessment output.

ScubaGear writes its report with a UTF-8 BOM and embeds presentation HTML in the
Requirement and Details fields (it renders the same structure to HTML). Both are
stripped here so downstream OSCAL artifacts carry clean prose.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path

from ..models import Assessment, PolicyResult

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def parse_assessment(path: str | Path, product: str = "AAD") -> Assessment:
    """Parse one product's results out of a ScubaGear report.

    Args:
        path: the ScubaResults JSON file.
        product: ScubaGear's product abbreviation - AAD, EXO, Defender,
            SharePoint, Teams, PowerPlatform.

    Raises:
        KeyError: if the report contains no results for ``product``.
    """
    # utf-8-sig transparently handles the BOM ScubaGear writes.
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))

    results_by_product = raw.get("Results", {})
    if product not in results_by_product:
        raise KeyError(
            f"no results for product {product!r}; "
            f"available: {sorted(results_by_product)}"
        )

    results: list[PolicyResult] = []
    for group in results_by_product[product]:
        group_number = str(group.get("GroupNumber", ""))
        group_name = group.get("GroupName", "")
        for control in group.get("Controls", []):
            results.append(
                PolicyResult(
                    policy_id=control["Control ID"],
                    result=control.get("Result", ""),
                    criticality=control.get("Criticality", ""),
                    details=_clean(control.get("Details", "")),
                    group_number=group_number,
                    group_name=group_name,
                )
            )

    meta = raw.get("MetaData", {})
    return Assessment(
        tenant_id=meta.get("TenantId", ""),
        tenant_name=meta.get("DisplayName", ""),
        product=product,
        tool=meta.get("Tool", "ScubaGear"),
        tool_version=meta.get("ToolVersion", ""),
        timestamp=_parse_timestamp(meta.get("TimestampZulu", "")),
        results=tuple(results),
    )


def _clean(text: str) -> str:
    """Strip embedded HTML and normalise whitespace."""
    if not text:
        return ""
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def _parse_timestamp(value: str) -> datetime:
    """Parse ScubaGear's Zulu timestamp into an aware datetime."""
    if not value:
        return datetime.now().astimezone()
    # "2026-05-04T17:15:48.307Z" - fromisoformat handles Z from Python 3.11.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
