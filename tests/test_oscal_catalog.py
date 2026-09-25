"""Rendering the SCuBA baseline as an OSCAL Catalog.

The catalog is the foundation artifact: every finding, POA&M item and crosswalk
link in the system ultimately references a control defined here.
"""

from datetime import datetime, timezone

import pytest

from regulator.oscal.catalog import build_catalog
from regulator.parsers.scuba_baseline import parse_baseline
from regulator.validation import validate

FIXED_TIME = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def baseline():
    return parse_baseline("data/sources/scuba/aad.md")


@pytest.fixture(scope="module")
def catalog(baseline):
    return build_catalog(baseline, last_modified=FIXED_TIME)


def test_the_catalog_is_valid_oscal(catalog):
    """The claim the whole project rests on."""
    result = validate(catalog, "catalog")
    assert result.valid, [str(e) for e in result.errors[:5]]


def test_has_a_catalog_root(catalog):
    assert "catalog" in catalog


def test_metadata_records_provenance(catalog):
    meta = catalog["catalog"]["metadata"]
    assert "Entra ID" in meta["title"] or "AAD" in meta["title"]
    assert meta["oscal-version"].startswith("1.")
    assert meta["last-modified"].startswith("2026-09-22")


def test_one_group_per_baseline_section(catalog, baseline):
    groups = catalog["catalog"]["groups"]
    assert len(groups) == len(baseline.groups)
    assert groups[0]["title"] == "Legacy Authentication"


def test_every_policy_becomes_a_control(catalog, baseline):
    ids = {c["id"] for g in catalog["catalog"]["groups"] for c in g["controls"]}
    assert len(ids) == len(baseline.policies)


def test_control_ids_are_derived_from_the_scuba_policy_id(catalog):
    ids = {c["id"] for g in catalog["catalog"]["groups"] for c in g["controls"]}
    assert "ms.aad.1.1v1" in ids


def test_control_title_is_the_requirement(catalog):
    control = _find(catalog, "ms.aad.1.1v1")
    assert control["title"] == "Legacy authentication SHALL be blocked."


def test_control_carries_the_original_policy_id_as_a_prop(catalog):
    """Round-tripping back to the source ID must never depend on string surgery."""
    control = _find(catalog, "ms.aad.1.1v1")
    props = {p["name"]: p["value"] for p in control["props"]}
    assert props["scuba-policy-id"] == "MS.AAD.1.1v1"
    assert props["criticality"] == "SHALL"


def test_bod_mandated_controls_are_flagged(catalog):
    control = _find(catalog, "ms.aad.1.1v1")
    props = {p["name"]: p["value"] for p in control["props"]}
    assert props["bod-25-01"] == "required"


def test_statement_part_holds_the_requirement(catalog):
    control = _find(catalog, "ms.aad.1.1v1")
    statement = next(p for p in control["parts"] if p["name"] == "statement")
    assert "Legacy authentication" in statement["prose"]


def test_rationale_is_preserved_as_guidance(catalog):
    control = _find(catalog, "ms.aad.1.1v1")
    guidance = next(p for p in control["parts"] if p["name"] == "guidance")
    assert "do not support MFA" in guidance["prose"]


def test_cisas_nist_mapping_becomes_links(catalog):
    """CISA's published mapping is carried through as first-class OSCAL links,
    tagged with its source so it is never confused with our AI-derived ones."""
    control = _find(catalog, "ms.aad.3.1v1")
    hrefs = [link["href"] for link in control["links"] if link["rel"] == "related"]
    assert "#ia-2.1" in hrefs


def test_rendering_is_deterministic(baseline):
    """Same input, same bytes - required for a reproducible audit artifact."""
    import json

    a = json.dumps(build_catalog(baseline, last_modified=FIXED_TIME), sort_keys=True)
    b = json.dumps(build_catalog(baseline, last_modified=FIXED_TIME), sort_keys=True)
    assert a == b


def _find(catalog, control_id):
    for group in catalog["catalog"]["groups"]:
        for control in group["controls"]:
            if control["id"] == control_id:
                return control
    raise AssertionError(f"control {control_id} not in catalog")
