"""Parsing CISA's SCuBA Secure Configuration Baseline markdown.

These tests run against the real published baseline in data/sources/scuba, not a
fixture, because the parser's whole job is to survive the actual document. Every
expected value below was read out of that file by hand.
"""

import pytest

from regulator.parsers.scuba_baseline import parse_baseline

BASELINE = "data/sources/scuba/aad.md"


@pytest.fixture(scope="module")
def baseline():
    return parse_baseline(BASELINE)


def test_identifies_the_product(baseline):
    assert baseline.product == "AAD"


def test_finds_every_numbered_section(baseline):
    """The Entra ID baseline is organised into numbered sections. CISA added a
    ninth, 'AI Security', after the earlier published descriptions of eight -
    so this asserts contiguous numbering rather than a frozen count."""
    numbers = [g.number for g in baseline.groups]
    assert numbers == [str(i) for i in range(1, len(numbers) + 1)]
    assert len(numbers) >= 8


def test_reads_the_ai_security_section(baseline):
    """Regression guard for the section CISA added most recently."""
    assert "AI Security" in [g.name for g in baseline.groups]


def test_section_names_are_read_without_their_numbering(baseline):
    by_number = {g.number: g.name for g in baseline.groups}
    assert by_number["1"] == "Legacy Authentication"
    assert by_number["3"] == "Strong Authentication and a Secure Registration Process"


def test_implementation_instructions_are_not_mistaken_for_policies(baseline):
    """'#### MS.AAD.2.1v1 Instructions' appears under Implementation and is not
    a policy. One of them is even written with a double space after the ####."""
    assert not any("Instruction" in p.id for p in baseline.policies)
    assert all(p.id.startswith("MS.AAD.") for p in baseline.policies)


def test_policy_ids_are_unique(baseline):
    ids = [p.id for p in baseline.policies]
    assert len(ids) == len(set(ids))


def test_reads_a_simple_policy(baseline):
    p = baseline.policy("MS.AAD.1.1v1")
    assert p.requirement == "Legacy authentication SHALL be blocked."
    assert p.criticality == "SHALL"
    assert p.group_number == "1"
    assert p.group_name == "Legacy Authentication"


def test_requirement_stops_at_the_first_paragraph(baseline):
    """MS.AAD.3.1v1 is followed by several paragraphs of guidance. The
    requirement is the first sentence only; the rest is not part of it."""
    p = baseline.policy("MS.AAD.3.1v1")
    assert p.requirement == "Phishing-resistant MFA SHALL be enforced for all users."


def test_requirement_excludes_the_html_badge_markup(baseline):
    """Each policy is followed by shields.io badge images that must not leak
    into the control statement."""
    for p in baseline.policies:
        assert "img.shields.io" not in p.requirement
        assert "<div" not in p.requirement


def test_reads_the_rationale(baseline):
    p = baseline.policy("MS.AAD.1.1v1")
    assert p.rationale is not None
    assert "do not support MFA" in p.rationale


def test_reads_cisas_own_nist_mapping(baseline):
    """CISA publishes a hand-authored NIST SP 800-53 mapping per policy. This is
    the ground truth the crosswalk agent is later measured against."""
    assert baseline.policy("MS.AAD.1.1v1").nist_controls == ("CM-7",)
    assert baseline.policy("MS.AAD.3.1v1").nist_controls == (
        "IA-2(1)",
        "IA-2(2)",
        "IA-5c",
        "IA-5g",
        "IA-2(8)",
    )


def test_most_policies_carry_a_nist_mapping(baseline):
    mapped = [p for p in baseline.policies if p.nist_controls]
    assert len(mapped) > len(baseline.policies) * 0.8


def test_reads_mitre_attack_techniques(baseline):
    p = baseline.policy("MS.AAD.1.1v1")
    assert "T1110" in p.mitre_techniques
    assert "T1078" in p.mitre_techniques


def test_detects_the_bod_25_01_requirement_badge(baseline):
    """The badge marks which policies are compulsory under the directive."""
    assert baseline.policy("MS.AAD.1.1v1").bod_25_01 is True


def test_criticality_is_normalised_to_shall_or_should(baseline):
    assert {p.criticality for p in baseline.policies} <= {"SHALL", "SHOULD"}


def test_unknown_policy_raises(baseline):
    with pytest.raises(KeyError):
        baseline.policy("MS.AAD.99.9v1")
