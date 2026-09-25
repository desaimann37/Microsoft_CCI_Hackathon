"""Validation of generated artifacts against NIST's published OSCAL schemas.

Correctness in this project is not a matter of opinion: an artifact is valid
because NIST's schema says so. Everything Regulator emits passes through here
before it is written to disk.

Two properties of the published OSCAL schemas need handling:

``$id`` on subschemas
    The schemas carry ``"$id": "#/definitions/oscal-catalog-...:catalog"`` on
    nested subschemas. Under JSON Schema resolution rules that resets the base
    URI, after which sibling references like ``#/definitions/UUIDDatatype``
    resolve against the subschema and fail. The ids are redundant - every
    reference in the document is a plain JSON pointer - so they are removed
    before use.

ECMA-262 regex
    OSCAL patterns use Unicode property escapes such as ``\\p{L}``. Python's
    ``re`` cannot compile these, so the ``pattern`` keyword is reimplemented on
    top of the third-party ``regex`` module, which can. Weakening or skipping
    those patterns was rejected: it would let malformed tokens through silently,
    which is precisely the failure this module exists to prevent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import paths

import regex as _regex
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as _JsonSchemaValidationError
from jsonschema import validators

#: OSCAL model name -> schema filename.
OSCAL_MODELS: dict[str, str] = {
    "catalog": "oscal_catalog_schema.json",
    "profile": "oscal_profile_schema.json",
    "component-definition": "oscal_component_schema.json",
    "assessment-results": "oscal_assessment-results_schema.json",
    "poam": "oscal_poam_schema.json",
}

#: The OSCAL release these schemas came from. Pinned deliberately - mixing
#: versions across artifacts is a silent, expensive failure.
OSCAL_VERSION = "1.2.3"

DEFAULT_SCHEMA_DIR = paths.SCHEMA_DIR


@dataclass(frozen=True)
class ValidationError:
    """One schema violation, with enough location detail to act on."""

    path: str
    message: str
    schema_path: str = ""

    def __str__(self) -> str:
        where = self.path or "<root>"
        return f"{where}: {self.message}"


@dataclass
class ValidationResult:
    model: str
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid

    def raise_if_invalid(self) -> None:
        """Fail loudly. A quiet wrong answer is the worst outcome here."""
        if not self.valid:
            detail = "\n  ".join(str(e) for e in self.errors[:10])
            more = (
                f"\n  ... and {len(self.errors) - 10} more"
                if len(self.errors) > 10
                else ""
            )
            raise InvalidArtifact(
                f"{self.model} artifact failed OSCAL {OSCAL_VERSION} "
                f"schema validation with {len(self.errors)} error(s):\n  "
                f"{detail}{more}"
            )


class InvalidArtifact(Exception):
    """Raised when an artifact does not conform to its OSCAL schema."""


def _pattern(validator, patrn, instance, schema):  # noqa: ANN001
    """``pattern`` keyword backed by ``regex`` so ``\\p{L}`` compiles."""
    if not isinstance(instance, str):
        return
    try:
        matched = _regex.search(patrn, instance) is not None
    except _regex.error as exc:  # pragma: no cover - malformed schema pattern
        raise InvalidArtifact(f"uncompilable schema pattern {patrn!r}: {exc}") from exc
    if not matched:
        yield _JsonSchemaValidationError(f"{instance!r} does not match {patrn!r}")


#: Draft 2020-12 validator with ECMA-262-compatible pattern support.
OscalValidator = validators.extend(Draft202012Validator, {"pattern": _pattern})


def _strip_subschema_ids(node: Any) -> Any:
    """Remove ``$id`` keys so ``#/definitions/...`` refs resolve from the root."""
    if isinstance(node, dict):
        node.pop("$id", None)
        for value in node.values():
            _strip_subschema_ids(value)
    elif isinstance(node, list):
        for value in node:
            _strip_subschema_ids(value)
    return node


@lru_cache(maxsize=None)
def load_schema(model: str, schema_dir: str = str(DEFAULT_SCHEMA_DIR)) -> Any:
    """Load and prepare one OSCAL model schema. Cached - they are large."""
    if model not in OSCAL_MODELS:
        raise KeyError(
            f"unknown OSCAL model {model!r}; known: {sorted(OSCAL_MODELS)}"
        )
    path = Path(schema_dir) / OSCAL_MODELS[model]
    if not path.exists():
        raise FileNotFoundError(
            f"OSCAL schema not found at {path}. "
            f"Run 'regulator fetch' to download the OSCAL {OSCAL_VERSION} schemas."
        )
    return _strip_subschema_ids(json.loads(path.read_text(encoding="utf-8")))


@lru_cache(maxsize=None)
def _validator_for(model: str, schema_dir: str) -> Any:
    return OscalValidator(load_schema(model, schema_dir))


def validate(
    document: Any, model: str, schema_dir: str | Path = DEFAULT_SCHEMA_DIR
) -> ValidationResult:
    """Validate ``document`` against the named OSCAL model schema.

    Args:
        document: the parsed JSON document (the full object, including its
            root key such as ``"catalog"``).
        model: one of :data:`OSCAL_MODELS`.

    Raises:
        KeyError: if ``model`` is not a known OSCAL model.
    """
    validator = _validator_for(model, str(schema_dir))
    errors = [
        ValidationError(
            path="/".join(str(p) for p in err.absolute_path),
            message=err.message,
            schema_path="/".join(str(p) for p in err.absolute_schema_path),
        )
        for err in validator.iter_errors(document)
    ]
    return ValidationResult(model=model, valid=not errors, errors=errors)
