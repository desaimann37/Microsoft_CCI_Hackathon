"""Candidate retrieval for the crosswalk.

The crosswalk agent can only propose controls it is shown. Early evaluation
runs scored poorly for a reason that had nothing to do with the model: for
MS.AAD.3.1v1 ("Phishing-resistant MFA SHALL be enforced for all users"), CISA's
answer is ia-2(1), ia-2(2), ia-2(8) and ia-5 - and pure lexical overlap never
retrieved any of them, because the policy text and the control text share
almost no vocabulary.

Retrieval therefore blends two signals: lexical similarity, and the control
families a practitioner would expect given the policy's subject matter. These
tests encode the failures that motivated it.
"""

import pytest

from regulator.families import likely_families
from regulator.nist_catalog import NistCatalog

MFA_POLICY = "Phishing-resistant MFA SHALL be enforced for all users."
LEGACY_POLICY = "Legacy authentication SHALL be blocked."
LOGGING_POLICY = "Security logs SHALL be sent to the agency's SOC for monitoring."


@pytest.fixture(scope="module")
def catalog():
    return NistCatalog.load("data/sources/nist/sp800-53r5-catalog.json")


def test_identifies_the_identity_family_from_mfa_language():
    assert "ia" in likely_families(MFA_POLICY)


def test_identifies_the_audit_family_from_logging_language():
    assert "au" in likely_families(LOGGING_POLICY)


def test_identifies_configuration_family_from_legacy_protocol_language():
    assert "cm" in likely_families(LEGACY_POLICY)


def test_unrelated_text_infers_no_family():
    assert likely_families("The weather is pleasant today.") == set()


def test_family_targeted_search_surfaces_ia_2_for_mfa(catalog):
    """The exact regression: ia-2 enhancements must be retrievable for MFA."""
    hits = catalog.search(MFA_POLICY, limit=24, families=likely_families(MFA_POLICY))
    assert any(h.startswith("ia-2") for h in hits), hits[:12]


def test_family_targeted_search_still_respects_the_limit(catalog):
    hits = catalog.search(MFA_POLICY, limit=20, families={"ia", "ac"})
    assert len(hits) <= 20


def test_results_are_deduplicated(catalog):
    hits = catalog.search(MFA_POLICY, limit=30, families={"ia"})
    assert len(hits) == len(set(hits))


def test_search_without_families_still_works(catalog):
    assert catalog.search("least functionality", limit=5)


def test_lexical_hits_are_not_displaced_entirely(catalog):
    """Family targeting augments lexical retrieval, it does not replace it."""
    plain = catalog.search(LEGACY_POLICY, limit=12)
    blended = catalog.search(LEGACY_POLICY, limit=24, families={"cm"})
    assert set(plain) & set(blended)


def test_engine_retrieves_ia_2_candidates_for_the_mfa_policy(catalog):
    """End to end: the engine's own candidate list must contain the answer."""
    from regulator.agents.crosswalk import CrosswalkEngine
    from regulator.agents.heuristic import HeuristicProvider
    from regulator.parsers.scuba_baseline import parse_baseline

    baseline = parse_baseline("data/sources/scuba/aad.md")
    engine = CrosswalkEngine(catalog, HeuristicProvider(catalog))
    policy = baseline.policy("MS.AAD.3.1v1")
    candidates = engine.candidates_for(policy)
    assert any(c.startswith("ia-2") for c in candidates), candidates
