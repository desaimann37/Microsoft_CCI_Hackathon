"""An index over NIST SP 800-53 Rev 5, published by NIST already in OSCAL.

This module is the hallucination guard. Every control identifier an AI agent
proposes is checked against this index before it can appear in an artifact, so
an invented reference is structurally incapable of reaching the output.
"""

import pytest

from regulator.nist_catalog import NistCatalog

CATALOG = "data/sources/nist/sp800-53r5-catalog.json"


@pytest.fixture(scope="module")
def catalog():
    return NistCatalog.load(CATALOG)


def test_indexes_every_control_including_enhancements(catalog):
    """1196 controls: the base controls plus their numbered enhancements."""
    assert len(catalog) == 1196


def test_knows_a_real_base_control(catalog):
    assert catalog.exists("cm-7")


def test_knows_a_real_enhancement(catalog):
    assert catalog.exists("ia-2.1")


def test_rejects_an_invented_control(catalog):
    """The whole point: a hallucinated ID must not resolve."""
    assert not catalog.exists("zz-99")
    assert not catalog.exists("ia-2.999")


def test_exposes_control_titles(catalog):
    assert catalog.title("cm-7") == "Least Functionality"


def test_resolves_nists_parenthesised_enhancement_notation(catalog):
    """CISA writes IA-2(1); OSCAL addresses it as ia-2.1."""
    assert catalog.resolve("IA-2(1)") == "ia-2.1"


def test_resolves_a_plain_control_reference(catalog):
    assert catalog.resolve("CM-7") == "cm-7"


def test_resolves_a_statement_level_reference_to_its_control(catalog):
    """CISA sometimes cites a statement item, e.g. IA-5c. There is no 'ia-5c'
    control - the statement belongs to ia-5, which is what it must resolve to."""
    assert catalog.resolve("IA-5c") == "ia-5"


def test_unresolvable_reference_returns_none(catalog):
    assert catalog.resolve("NOT-A-CONTROL") is None


def test_exposes_the_control_family(catalog):
    assert catalog.family("ia-2.1") == "ia"


def test_search_finds_controls_by_keyword(catalog):
    """Used to retrieve candidate controls for the crosswalk agent."""
    hits = catalog.search("multi-factor authentication", limit=10)
    assert hits
    assert any(h.startswith("ia-2") for h in hits)


def test_search_respects_the_limit(catalog):
    assert len(catalog.search("access", limit=5)) <= 5


def test_control_text_is_available_for_grounding(catalog):
    """The agent must reason over the real control statement, not just the id."""
    text = catalog.text("cm-7")
    assert "least functionality" in text.lower() or "essential" in text.lower()
