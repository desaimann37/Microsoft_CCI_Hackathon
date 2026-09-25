"""OSCAL Profile and Component Definition.

The Profile is how OSCAL expresses "a meaningful subset of the baseline", which
is exactly what the challenge brief asks for - answered in the standard's own
idiom rather than as an ad-hoc filtered list.

The Component Definition is the bridge between an abstract requirement and the
concrete tenant setting that satisfies it.
"""

from datetime import datetime, timezone

import pytest

from regulator.oscal.component import build_component_definition
from regulator.oscal.profile import build_profile
from regulator.parsers.scuba_baseline import parse_baseline
from regulator.validation import validate

FIXED_TIME = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
CATALOG_HREF = "scuba-catalog-aad.json"


@pytest.fixture(scope="module")
def baseline():
    return parse_baseline("data/sources/scuba/aad.md")


# --------------------------------------------------------------------- profile


@pytest.fixture(scope="module")
def profile(baseline):
    return build_profile(baseline, catalog_href=CATALOG_HREF, last_modified=FIXED_TIME)


def test_profile_is_valid_oscal(profile):
    result = validate(profile, "profile")
    assert result.valid, [str(e) for e in result.errors[:5]]


def test_profile_imports_the_catalog(profile):
    imports = profile["profile"]["imports"]
    assert imports[0]["href"] == CATALOG_HREF


def test_full_profile_selects_every_control(profile, baseline):
    included = profile["profile"]["imports"][0]["include-controls"][0]["with-ids"]
    assert len(included) == len(baseline.policies)


def test_bod_subset_profile_is_smaller_and_valid(baseline):
    """The BOD 25-01 mandated policies are the subset agencies must implement."""
    sub = build_profile(
        baseline,
        catalog_href=CATALOG_HREF,
        last_modified=FIXED_TIME,
        only_bod_25_01=True,
    )
    assert validate(sub, "profile").valid
    ids = sub["profile"]["imports"][0]["include-controls"][0]["with-ids"]
    assert 0 < len(ids) < len(baseline.policies)


def test_bod_subset_contains_only_mandated_controls(baseline):
    sub = build_profile(
        baseline,
        catalog_href=CATALOG_HREF,
        last_modified=FIXED_TIME,
        only_bod_25_01=True,
    )
    ids = set(sub["profile"]["imports"][0]["include-controls"][0]["with-ids"])
    mandated = {p.id.lower() for p in baseline.policies if p.bod_25_01}
    assert ids == mandated


# ------------------------------------------------------------------- component


@pytest.fixture(scope="module")
def component(baseline):
    return build_component_definition(
        baseline, catalog_href=CATALOG_HREF, last_modified=FIXED_TIME
    )


def test_component_definition_is_valid_oscal(component):
    result = validate(component, "component-definition")
    assert result.valid, [str(e) for e in result.errors[:5]]


def test_describes_the_entra_id_service(component):
    comp = component["component-definition"]["components"][0]
    assert comp["type"] == "service"
    assert "Entra" in comp["title"] or "AAD" in comp["title"]


def test_every_policy_has_an_implemented_requirement(component, baseline):
    impls = component["component-definition"]["components"][0][
        "control-implementations"
    ][0]["implemented-requirements"]
    assert len(impls) == len(baseline.policies)


def test_implemented_requirement_points_at_a_catalog_control(component):
    impls = component["component-definition"]["components"][0][
        "control-implementations"
    ][0]["implemented-requirements"]
    assert any(i["control-id"] == "ms.aad.1.1v1" for i in impls)
