"""Deterministic identifiers.

OSCAL requires UUIDs throughout, and artifacts cross-reference each other by
UUID. If those UUIDs were random, every pipeline run would emit documents whose
references no longer resolve against the previous run's. Auditors re-running the
tool must get byte-identical output, so identity is derived from stable source
keys instead.
"""

import re

from regulator.ids import deterministic_uuid

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def test_same_parts_produce_the_same_uuid():
    assert deterministic_uuid("control", "MS.AAD.1.1v1") == deterministic_uuid(
        "control", "MS.AAD.1.1v1"
    )


def test_different_parts_produce_different_uuids():
    assert deterministic_uuid("control", "MS.AAD.1.1v1") != deterministic_uuid(
        "control", "MS.AAD.3.1v1"
    )


def test_kind_is_part_of_identity():
    """A finding about a control is not the same object as the control."""
    assert deterministic_uuid("finding", "MS.AAD.1.1v1") != deterministic_uuid(
        "control", "MS.AAD.1.1v1"
    )


def test_output_is_a_well_formed_rfc4122_uuid():
    """OSCAL's schema constrains uuid fields to this pattern."""
    assert UUID_RE.match(deterministic_uuid("control", "MS.AAD.1.1v1"))


def test_parts_are_not_ambiguously_joined():
    """('ab', 'c') and ('a', 'bc') are different identities, not the same one."""
    assert deterministic_uuid("ab", "c") != deterministic_uuid("a", "bc")
