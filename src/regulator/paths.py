"""Locations of the data that ships with Regulator.

Every default here is resolved from this file's own location rather than the
current working directory. A developer runs the CLI from the repository root; a
hosting platform starts the process from wherever it likes. Relative defaults
work in the first case and fail in the second, which is the most common way a
working application dies on its first deployment.

Callers may still pass explicit paths - these are only the defaults.
"""

from __future__ import annotations

from pathlib import Path

#: src/regulator/paths.py -> src/regulator -> src -> repository root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DATA_DIR = REPO_ROOT / "data"

#: NIST's published OSCAL schemas, pinned to one release.
SCHEMA_DIR = DATA_DIR / "schemas"

#: CISA's SCuBA Secure Configuration Baselines, one markdown file per product.
BASELINE_DIR = DATA_DIR / "sources" / "scuba"

#: NIST SP 800-53 Rev 5, as published by NIST in OSCAL form.
NIST_CATALOG = DATA_DIR / "sources" / "nist" / "sp800-53r5-catalog.json"

#: CISA's own published sample ScubaGear report, used by the demo and tests.
SAMPLE_REPORT = DATA_DIR / "sources" / "scubagear" / "ScubaResults-sample.json"
