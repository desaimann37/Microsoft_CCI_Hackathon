"""The crosswalk engine: SCuBA policy -> NIST SP 800-53 controls.

The engine is deliberately separated from whatever proposes the mappings. A
provider (heuristic or LLM) suggests; the engine validates, normalises and
scores. That split is what makes the hallucination guard a structural property
rather than a hopeful instruction in a prompt.
"""

import pytest

from regulator.agents.crosswalk import RELATIONSHIPS, CrosswalkEngine
from regulator.agents.heuristic import HeuristicProvider
from regulator.nist_catalog import NistCatalog
from regulator.parsers.scuba_baseline import parse_baseline


@pytest.fixture(scope="module")
def catalog():
    return NistCatalog.load("data/sources/nist/sp800-53r5-catalog.json")


@pytest.fixture(scope="module")
def baseline():
    return parse_baseline("data/sources/scuba/aad.md")


@pytest.fixture(scope="module")
def engine(catalog):
    return CrosswalkEngine(catalog, HeuristicProvider(catalog))


def test_proposes_mappings_for_a_policy(engine, baseline):
    mappings = engine.map_policy(baseline.policy("MS.AAD.3.1v1"))
    assert mappings


def test_every_proposed_control_is_real(engine, baseline, catalog):
    """The guarantee the whole design turns on."""
    for policy in baseline.policies:
        for mapping in engine.map_policy(policy):
            assert catalog.exists(mapping.control_id), mapping.control_id


def test_confidence_is_a_probability(engine, baseline):
    for mapping in engine.map_policy(baseline.policy("MS.AAD.3.1v1")):
        assert 0.0 <= mapping.confidence <= 1.0


def test_relationship_is_from_the_closed_vocabulary(engine, baseline):
    for mapping in engine.map_policy(baseline.policy("MS.AAD.3.1v1")):
        assert mapping.relationship in RELATIONSHIPS


def test_mappings_record_which_policy_they_came_from(engine, baseline):
    for mapping in engine.map_policy(baseline.policy("MS.AAD.1.1v1")):
        assert mapping.policy_id == "MS.AAD.1.1v1"


def test_mappings_carry_a_rationale(engine, baseline):
    """An unexplained mapping cannot be reviewed, so it is not useful."""
    for mapping in engine.map_policy(baseline.policy("MS.AAD.1.1v1")):
        assert mapping.rationale.strip()


def test_invented_control_ids_are_discarded(catalog, baseline):
    """A provider that hallucinates must not be able to poison an artifact."""

    class Hallucinating:
        def propose(self, policy, candidates):
            return [
                {"control_id": "zz-99", "relationship": "satisfies",
                 "confidence": 0.99, "rationale": "invented"},
                {"control_id": "ia-2.999", "relationship": "satisfies",
                 "confidence": 0.99, "rationale": "also invented"},
                {"control_id": "cm-7", "relationship": "supports",
                 "confidence": 0.8, "rationale": "real"},
            ]

    engine = CrosswalkEngine(catalog, Hallucinating())
    mappings = engine.map_policy(baseline.policy("MS.AAD.1.1v1"))
    assert [m.control_id for m in mappings] == ["cm-7"]


def test_unparseable_provider_output_is_survived(catalog, baseline):
    """A model that returns the wrong shape degrades to no mappings, not a crash."""

    class Broken:
        def propose(self, policy, candidates):
            return [{"nonsense": True}, "not even a dict"]

    engine = CrosswalkEngine(catalog, Broken())
    assert engine.map_policy(baseline.policy("MS.AAD.1.1v1")) == []


def test_unknown_relationship_falls_back_to_related(catalog, baseline):
    class Odd:
        def propose(self, policy, candidates):
            return [{"control_id": "cm-7", "relationship": "vibes",
                     "confidence": 0.5, "rationale": "x"}]

    engine = CrosswalkEngine(catalog, Odd())
    assert engine.map_policy(baseline.policy("MS.AAD.1.1v1"))[0].relationship == "related"


def test_confidence_is_clamped(catalog, baseline):
    class Overconfident:
        def propose(self, policy, candidates):
            return [{"control_id": "cm-7", "relationship": "satisfies",
                     "confidence": 42, "rationale": "x"}]

    engine = CrosswalkEngine(catalog, Overconfident())
    assert engine.map_policy(baseline.policy("MS.AAD.1.1v1"))[0].confidence == 1.0


def test_duplicate_suggestions_are_collapsed(catalog, baseline):
    class Repetitive:
        def propose(self, policy, candidates):
            return [
                {"control_id": "cm-7", "relationship": "satisfies",
                 "confidence": 0.6, "rationale": "first"},
                {"control_id": "cm-7", "relationship": "supports",
                 "confidence": 0.9, "rationale": "second"},
            ]

    engine = CrosswalkEngine(catalog, Repetitive())
    mappings = engine.map_policy(baseline.policy("MS.AAD.1.1v1"))
    assert len(mappings) == 1
    assert mappings[0].confidence == 0.9  # the stronger claim wins


def test_cisa_mappings_are_loaded_separately_as_ground_truth(engine, baseline):
    """CISA's own published mapping is never mixed into AI output."""
    truth = engine.cisa_mapping(baseline.policy("MS.AAD.1.1v1"))
    assert truth == ["cm-7"]
    assert all(m.source != "cisa" for m in engine.map_policy(baseline.policy("MS.AAD.1.1v1")))
