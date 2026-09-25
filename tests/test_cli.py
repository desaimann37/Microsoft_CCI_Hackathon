"""The command line interface.

Thin by design - it orchestrates, formats and sets exit codes. The exit codes
matter most: this tool is meant to run in CI, where a non-zero status on an
invalid artifact is what stops bad evidence reaching an auditor.
"""

import json

from typer.testing import CliRunner

from regulator.cli import app

runner = CliRunner()
SCUBAGEAR = "data/sources/scubagear/ScubaResults-sample.json"


def test_build_produces_artifacts(tmp_path):
    result = runner.invoke(
        app, ["build", SCUBAGEAR, "--product", "AAD", "--out", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert len(list(tmp_path.glob("*.json"))) == 5


def test_build_reports_validation_status(tmp_path):
    result = runner.invoke(app, ["build", SCUBAGEAR, "--out", str(tmp_path)])
    assert "VALID" in result.output


def test_build_reports_the_posture_summary(tmp_path):
    result = runner.invoke(app, ["build", SCUBAGEAR, "--out", str(tmp_path)])
    assert "11" in result.output  # failures in the sample tenant


def test_build_names_the_ai_backend(tmp_path):
    """Provenance must be visible without reading the artifacts."""
    result = runner.invoke(app, ["build", SCUBAGEAR, "--out", str(tmp_path)])
    assert "heuristic" in result.output.lower() or "foundry" in result.output.lower()


def test_validate_accepts_a_good_artifact(tmp_path):
    runner.invoke(app, ["build", SCUBAGEAR, "--out", str(tmp_path)])
    target = tmp_path / "scuba-catalog-aad.json"
    result = runner.invoke(app, ["validate", str(target), "--model", "catalog"])
    assert result.exit_code == 0
    assert "VALID" in result.output


def test_validate_rejects_a_bad_artifact_with_nonzero_exit(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"catalog": {}}), encoding="utf-8")
    result = runner.invoke(app, ["validate", str(bad), "--model", "catalog"])
    assert result.exit_code != 0
    assert "INVALID" in result.output


def test_evaluate_reports_both_scores():
    result = runner.invoke(app, ["evaluate", "--product", "AAD"])
    assert result.exit_code == 0
    assert "exact" in result.output.lower()
    assert "family" in result.output.lower()


def test_query_answers_from_artifacts(tmp_path):
    result = runner.invoke(
        app,
        ["query", "Which controls failed?", "--source", SCUBAGEAR, "--out", str(tmp_path)],
    )
    assert result.exit_code == 0
    assert "MS.AAD." in result.output
