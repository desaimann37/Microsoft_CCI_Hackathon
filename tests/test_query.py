"""Natural-language querying over the generated artifacts.

The query agent reasons over our *structured output*, not over raw documents.
That is the payoff for having built the OSCAL model properly: the answer to
"what should we fix first?" is already in the data.

Citations are enforced rather than encouraged. An answer that cites a policy ID
absent from the artifacts is dropped, because an unverifiable citation in a
compliance answer is worse than no citation.
"""

import pytest

from regulator.pipeline import Pipeline
from regulator.query import QueryEngine

SCUBAGEAR = "data/sources/scubagear/ScubaResults-sample.json"


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    out = tmp_path_factory.mktemp("q")
    return Pipeline().run(SCUBAGEAR, product="AAD", output_dir=out)


@pytest.fixture(scope="module")
def engine(run):
    return QueryEngine.from_run(run)


def test_builds_a_context_from_the_artifacts(engine):
    context = engine.context()
    assert "MS.AAD." in context
    assert len(context) > 200


def test_context_includes_failures(engine):
    assert "MS.AAD.3.1v1" in engine.context()


def test_context_is_bounded(engine):
    """A context that grows without limit will eventually exceed the model's."""
    assert len(engine.context(max_chars=1500)) <= 1500


def test_answers_a_question(engine):
    answer = engine.ask("Which controls failed?")
    assert answer.text.strip()


def test_answer_carries_citations(engine):
    answer = engine.ask("Which controls failed?")
    assert answer.citations


def test_every_citation_resolves_to_a_real_policy(engine):
    """The guard: an unverifiable citation must never be shown."""
    answer = engine.ask("Which controls failed?")
    known = engine.known_policy_ids()
    assert all(c in known for c in answer.citations)


def test_invented_citations_are_stripped(run):
    """A provider that cites something absent gets that citation removed."""

    class Fabricating:
        def answer(self, question, context):
            return {
                "answer": "Everything is fine.",
                "citations": ["MS.AAD.1.1v1", "MS.AAD.99.9v1", "TOTALLY.MADE.UP"],
            }

    engine = QueryEngine.from_run(run, provider=Fabricating())
    answer = engine.ask("anything")
    assert answer.citations == ["MS.AAD.1.1v1"]
    assert answer.dropped_citations == ["MS.AAD.99.9v1", "TOTALLY.MADE.UP"]


def test_provider_failure_degrades_gracefully(run):
    class Exploding:
        def answer(self, question, context):
            raise RuntimeError("model unavailable")

    engine = QueryEngine.from_run(run, provider=Exploding())
    answer = engine.ask("anything")
    assert answer.citations == []
    assert "unavailable" in answer.text.lower() or "could not" in answer.text.lower()


def test_known_policy_ids_come_from_the_artifacts(engine, run):
    assert len(engine.known_policy_ids()) == run.summary["total"]
