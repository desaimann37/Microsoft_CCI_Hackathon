"""The web dashboard.

Deliberately modest. The interface exists to make the system legible - to a
reviewer, and on a demo recording - not to be the product. The artifacts and
their validation status are the product.
"""

import pytest
from fastapi.testclient import TestClient

from regulator.web import create_app

SCUBAGEAR = "data/sources/scubagear/ScubaResults-sample.json"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    app = create_app(SCUBAGEAR, "AAD", output_dir=tmp_path_factory.mktemp("web"))
    return TestClient(app)


def test_dashboard_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Regulator" in response.text


def test_dashboard_shows_the_tenant(client):
    assert "tqhjy" in client.get("/").text


def test_dashboard_shows_the_validation_badge(client):
    """The proof, front and centre."""
    assert "VALID" in client.get("/").text


def test_summary_api_returns_counts(client):
    data = client.get("/api/summary").json()
    assert data["total"] == 30
    assert data["fail"] == 11


def test_artifacts_api_lists_all_five(client):
    data = client.get("/api/artifacts").json()
    assert len(data["artifacts"]) == 5
    assert all(a["valid"] for a in data["artifacts"])


def test_artifact_api_returns_the_document(client):
    data = client.get("/api/artifacts/catalog").json()
    assert "catalog" in data


def test_unknown_artifact_is_404(client):
    assert client.get("/api/artifacts/nope").status_code == 404


def test_findings_api_returns_ranked_failures(client):
    data = client.get("/api/findings").json()
    failures = [f for f in data["findings"] if f["result"] == "Fail"]
    assert len(failures) == 11
    assert failures[0]["policy_id"].startswith("MS.AAD.")


def test_poam_api_returns_items(client):
    data = client.get("/api/poam").json()
    assert len(data["items"]) == 11
    assert data["items"][0]["title"]


def test_query_api_answers_with_citations(client):
    response = client.post("/api/query", json={"question": "Which controls failed?"})
    assert response.status_code == 200
    data = response.json()
    assert data["answer"]
    assert isinstance(data["citations"], list)


def test_query_api_rejects_an_empty_question(client):
    assert client.post("/api/query", json={"question": "  "}).status_code == 422


def test_evaluation_api_returns_both_scores(client):
    data = client.get("/api/evaluation").json()
    assert "exact" in data and "family" in data
    assert 0.0 <= data["exact"]["f1"] <= 1.0
