"""OSCAL schema validation.

This is the module the whole project's correctness claim rests on: an artifact is
valid because NIST's published schema says so, not because we think it looks
right. Two OSCAL quirks are handled here and are worth knowing about:

  1. The schemas set ``$id`` on nested subschemas, which resets the JSON Schema
     resolution base and breaks every sibling ``#/definitions/...`` reference.
  2. The schemas use ECMA-262 regex features (``\\p{L}`` Unicode property
     escapes) that Python's ``re`` module cannot compile.

The headline test validates NIST's own SP 800-53 catalog against NIST's own
catalog schema. If that ever fails, the validator is broken, not the document.
"""

import json

import pytest

from regulator.validation import OSCAL_MODELS, ValidationError, validate

NIST_CATALOG = "data/sources/nist/sp800-53r5-catalog.json"


def test_all_five_model_schemas_load():
    """Catalog, profile, component definition, assessment results, POA&M."""
    assert set(OSCAL_MODELS) == {
        "catalog",
        "profile",
        "component-definition",
        "assessment-results",
        "poam",
    }


def test_nists_own_catalog_validates_against_nists_own_schema():
    """The end-to-end proof that validation is real and correctly wired."""
    doc = json.loads(open(NIST_CATALOG, encoding="utf-8").read())
    result = validate(doc, "catalog")
    assert result.valid, result.errors[:3]
    assert result.errors == []


def test_rejects_a_document_missing_required_fields():
    """An OSCAL catalog requires both uuid and metadata."""
    result = validate({"catalog": {}}, "catalog")
    assert not result.valid
    assert result.errors


def test_rejects_a_document_with_the_wrong_root_key():
    result = validate({"profile": {"uuid": "x"}}, "catalog")
    assert not result.valid


def test_errors_carry_a_location_path():
    """A bare 'invalid' is useless for the repair loop; it needs to know where."""
    bad = {
        "catalog": {
            "uuid": "not-a-uuid",
            "metadata": {
                "title": "T",
                "last-modified": "2026-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.1.2",
            },
        }
    }
    result = validate(bad, "catalog")
    assert not result.valid
    assert any("uuid" in e.path for e in result.errors)


def test_unicode_property_escapes_do_not_crash_the_validator():
    """OSCAL token patterns use \\p{L}; Python's re raises on them."""
    doc = {
        "catalog": {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "metadata": {
                "title": "T",
                "last-modified": "2026-01-01T00:00:00Z",
                "version": "1.0",
                "oscal-version": "1.1.2",
            },
            "controls": [{"id": "ac-1", "title": "Policy"}],
        }
    }
    result = validate(doc, "catalog")  # must not raise
    assert result.valid, result.errors[:3]


def test_unknown_model_raises():
    with pytest.raises(KeyError):
        validate({}, "not-a-model")


def test_validation_error_renders_readably():
    result = validate({"catalog": {}}, "catalog")
    assert isinstance(result.errors[0], ValidationError)
    assert str(result.errors[0])
