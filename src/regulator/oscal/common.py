"""Shared helpers for building OSCAL documents.

Everything here is deterministic. No timestamps are read from the clock, no
identifiers are randomly generated: a caller supplies the assessment time, and
identity is derived from source keys. That is what makes a Regulator artifact
reproducible, which an audit artifact has to be.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

#: The OSCAL specification version the emitted documents declare.
OSCAL_SPEC_VERSION = "1.1.2"

#: Tool provenance recorded in every artifact.
TOOL_NAME = "Regulator"
TOOL_VERSION = "0.1.0"

_TOKEN_CLEAN_RE = re.compile(r"[^a-z0-9._-]+")


def oscal_timestamp(value: datetime) -> str:
    """Format a datetime the way OSCAL's date-time-with-timezone expects."""
    if value.tzinfo is None:
        raise ValueError("OSCAL timestamps must carry a timezone")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def control_id(policy_id: str) -> str:
    """SCuBA policy ID -> OSCAL control ID (``MS.AAD.1.1v1`` -> ``ms.aad.1.1v1``)."""
    return _TOKEN_CLEAN_RE.sub("-", policy_id.lower())


def nist_control_id(control: str) -> str:
    """NIST control reference -> OSCAL catalog control ID.

    ``IA-2(1)`` -> ``ia-2.1``, ``CM-7`` -> ``cm-7``. NIST writes enhancements in
    parentheses; OSCAL addresses them with a dotted suffix.
    """
    out = control.strip().lower().replace("(", ".").replace(")", "")
    return _TOKEN_CLEAN_RE.sub("-", out).strip("-.")


def build_metadata(
    title: str,
    last_modified: datetime,
    *,
    version: str = "1.0.0",
    extra_props: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build an OSCAL metadata block."""
    metadata: dict[str, Any] = {
        "title": title,
        "last-modified": oscal_timestamp(last_modified),
        "version": version,
        "oscal-version": OSCAL_SPEC_VERSION,
        "props": [
            {"name": "generated-by", "value": f"{TOOL_NAME} {TOOL_VERSION}"},
        ],
    }
    if extra_props:
        metadata["props"].extend(extra_props)
    return metadata


def prop(name: str, value: str, **kwargs: str) -> dict[str, str]:
    """An OSCAL property. Values are always strings in OSCAL."""
    out = {"name": name, "value": str(value)}
    out.update(kwargs)
    return out


def link(href: str, rel: str, text: str | None = None) -> dict[str, str]:
    out = {"href": href, "rel": rel}
    if text:
        out["text"] = text
    return out


def part(name: str, prose: str, *, part_id: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"name": name, "prose": prose}
    if part_id:
        out["id"] = part_id
    return out


def scuba_source_resource(baseline_url: str, title: str) -> dict[str, Any]:
    """A back-matter resource pointing at the published CISA baseline.

    Traceability matters here: an auditor must be able to get from any control
    in our catalog back to the authoritative document it came from.
    """
    from ..ids import deterministic_uuid

    return {
        "uuid": deterministic_uuid("resource", baseline_url),
        "title": title,
        "rlinks": [{"href": baseline_url, "media-type": "text/markdown"}],
    }
