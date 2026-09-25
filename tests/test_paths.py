"""Bundled data paths must not depend on the working directory.

Every default data path in the project - the OSCAL schemas, the SCuBA baselines,
the SP 800-53 catalog, the sample report - ships inside the repository. Resolving
them against the current directory works on a developer's machine and fails the
moment a host starts the process from somewhere else, which is the single most
common way a working app dies on first deployment.
"""

from pathlib import Path

import pytest


def test_repo_root_contains_the_data_directory():
    from regulator.paths import DATA_DIR, REPO_ROOT

    assert (REPO_ROOT / "pyproject.toml").is_file()
    assert DATA_DIR.is_dir()


@pytest.mark.parametrize(
    "attr",
    ["SCHEMA_DIR", "BASELINE_DIR", "NIST_CATALOG", "SAMPLE_REPORT"],
)
def test_every_bundled_path_exists(attr):
    import regulator.paths as paths

    assert Path(getattr(paths, attr)).exists(), attr


@pytest.mark.parametrize(
    "attr",
    ["SCHEMA_DIR", "BASELINE_DIR", "NIST_CATALOG", "SAMPLE_REPORT"],
)
def test_every_bundled_path_is_absolute(attr):
    import regulator.paths as paths

    assert Path(getattr(paths, attr)).is_absolute(), attr


def test_pipeline_defaults_survive_a_directory_change(tmp_path, monkeypatch):
    """The real regression: run the pipeline from an unrelated directory."""
    from regulator.paths import SAMPLE_REPORT
    from regulator.pipeline import Pipeline

    monkeypatch.chdir(tmp_path)
    run = Pipeline().run(SAMPLE_REPORT, product="AAD", output_dir=tmp_path / "out")
    assert run.all_valid
    assert run.summary["total"] == 30


def test_validation_finds_its_schemas_from_anywhere(tmp_path, monkeypatch):
    from regulator.validation import validate

    monkeypatch.chdir(tmp_path)
    result = validate({"catalog": {}}, "catalog")
    # Invalid document, but it was validated - the schema was found.
    assert not result.valid
    assert result.errors
