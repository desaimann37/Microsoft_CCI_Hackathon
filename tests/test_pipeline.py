"""The end-to-end pipeline.

Sources in, five validated OSCAL artifacts out. This is the test that proves the
whole chain holds together, and the one that would fail first if any part of it
regressed.
"""

import json

import pytest

from regulator.pipeline import Pipeline
from regulator.validation import InvalidArtifact, validate

SCUBAGEAR = "data/sources/scubagear/ScubaResults-sample.json"


@pytest.fixture(scope="module")
def pipeline():
    return Pipeline()


@pytest.fixture(scope="module")
def run(pipeline, tmp_path_factory):
    out = tmp_path_factory.mktemp("artifacts")
    return pipeline.run(SCUBAGEAR, product="AAD", output_dir=out)


def test_produces_all_five_oscal_artifacts(run):
    assert set(run.artifacts) == {
        "catalog",
        "profile",
        "component-definition",
        "assessment-results",
        "poam",
    }


def test_every_artifact_validates_against_its_nist_schema(run):
    """The correctness claim, asserted end to end."""
    for model, document in run.artifacts.items():
        assert validate(document, model).valid, model


def test_reports_validation_status_for_each_artifact(run):
    assert all(run.validation[model] for model in run.artifacts)
    assert run.all_valid is True


def test_writes_each_artifact_to_disk(run):
    for path in run.written.values():
        assert path.exists()
        json.loads(path.read_text(encoding="utf-8"))


def test_summary_counts_match_the_assessment(run):
    assert run.summary["total"] == 30
    assert run.summary["pass"] == 12
    assert run.summary["fail"] == 11
    assert run.summary["warning"] == 4
    assert run.summary["not_applicable"] == 3


def test_poam_has_one_item_per_failure(run):
    items = run.artifacts["poam"]["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == run.summary["fail"]


def test_records_which_ai_backend_was_used(run):
    """Provenance: a reader must know whether a model was involved."""
    assert run.backend in {"foundry", "heuristic"}


def test_runs_without_any_azure_credentials(run, monkeypatch):
    """The deterministic core never depends on a model being reachable."""
    assert run.all_valid


def test_crosswalk_mappings_are_attached(run):
    assert run.analysis.mappings
    assert all(m.source == "ai" for m in run.analysis.mappings)


def test_risk_judgements_cover_every_failure(run):
    ranked = {r.policy_id for r in run.analysis.risks}
    assert len(ranked) == run.summary["fail"]


def test_remediations_cover_every_failure(run):
    drafted = {r.policy_id for r in run.analysis.remediations}
    assert len(drafted) == run.summary["fail"]


def test_rerunning_produces_identical_artifacts(pipeline, tmp_path):
    """Reproducibility: an auditor re-running the tool gets the same bytes."""
    a = pipeline.run(SCUBAGEAR, product="AAD", output_dir=tmp_path / "a")
    b = pipeline.run(SCUBAGEAR, product="AAD", output_dir=tmp_path / "b")
    for model in a.artifacts:
        assert json.dumps(a.artifacts[model], sort_keys=True) == json.dumps(
            b.artifacts[model], sort_keys=True
        )


def test_invalid_artifact_fails_loudly(pipeline, tmp_path, monkeypatch):
    """A quiet wrong answer is the worst possible outcome for this tool."""
    import regulator.pipeline as pipeline_mod

    def broken(*args, **kwargs):
        return {"catalog": {"uuid": "not-a-uuid"}}

    monkeypatch.setattr(pipeline_mod, "build_catalog", broken)
    with pytest.raises(InvalidArtifact):
        pipeline.run(SCUBAGEAR, product="AAD", output_dir=tmp_path / "bad")


def test_unknown_product_is_reported_clearly(pipeline, tmp_path):
    """The failure names the product and the path it looked for, so the user
    can act on it without reading the source."""
    with pytest.raises(FileNotFoundError, match="NOPE"):
        pipeline.run(SCUBAGEAR, product="NOPE", output_dir=tmp_path / "x")
