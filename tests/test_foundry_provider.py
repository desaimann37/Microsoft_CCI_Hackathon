"""The Microsoft Foundry provider.

The network call itself is a thin wrapper and is not unit tested here. What is
tested is everything around it, because that is where correctness actually
lives: how the prompt is assembled, how a model's reply is parsed, and how the
system behaves when Foundry is unreachable or misconfigured.

Prompt construction and response parsing are deliberately pure functions so they
can be exercised without credentials.
"""

import pytest

from regulator.agents.foundry import (
    build_crosswalk_prompt,
    is_configured,
    parse_crosswalk_response,
)
from regulator.agents.registry import build_providers
from regulator.nist_catalog import NistCatalog
from regulator.parsers.scuba_baseline import parse_baseline

ENV_VARS = (
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_DEPLOYMENT",
)


@pytest.fixture(scope="module")
def catalog():
    return NistCatalog.load("data/sources/nist/sp800-53r5-catalog.json")


@pytest.fixture(scope="module")
def policy():
    return parse_baseline("data/sources/scuba/aad.md").policy("MS.AAD.3.1v1")


# ----------------------------------------------------------- configuration


def test_not_configured_without_credentials(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    assert is_configured() is False


def test_configured_when_all_credentials_present(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "secret")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    assert is_configured() is True


def test_partial_credentials_are_not_enough(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_DEPLOYMENT", raising=False)
    assert is_configured() is False


def test_registry_falls_back_to_heuristics_without_credentials(monkeypatch, catalog):
    """The pipeline must run end to end with no Azure access at all."""
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    providers = build_providers(catalog)
    assert providers.backend == "heuristic"
    assert type(providers.crosswalk).__name__ == "HeuristicProvider"


def test_registry_selects_foundry_when_configured(monkeypatch, catalog):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "secret")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    providers = build_providers(catalog)
    assert providers.backend == "foundry"


# ------------------------------------------------------------------ prompt


def test_prompt_contains_the_policy_under_consideration(policy, catalog):
    prompt = build_crosswalk_prompt(policy, ["ia-2.1", "cm-7"], catalog)
    assert policy.id in prompt
    assert policy.requirement in prompt


def test_prompt_grounds_the_model_in_real_candidate_controls(policy, catalog):
    """The model chooses among retrieved controls; it does not recall them."""
    prompt = build_crosswalk_prompt(policy, ["ia-2.1", "cm-7"], catalog)
    assert "ia-2.1" in prompt
    assert catalog.title("cm-7") in prompt


def test_prompt_does_not_leak_cisas_answer(policy, catalog):
    """CISA's own mapping is ground truth for evaluation. Putting it in the
    prompt would make the measurement meaningless."""
    prompt = build_crosswalk_prompt(policy, ["ia-2.1", "cm-7"], catalog)
    assert "FedRAMP High Baseline Mapping" not in prompt
    # MS.AAD.3.1v1's truth includes ia-2.2 and ia-2.8, which are not candidates.
    assert "ia-2.2" not in prompt
    assert "ia-2.8" not in prompt


def test_prompt_states_the_closed_relationship_vocabulary(policy, catalog):
    prompt = build_crosswalk_prompt(policy, ["cm-7"], catalog)
    for relationship in ("satisfies", "supports", "related"):
        assert relationship in prompt


# ------------------------------------------------------------------ parsing


def test_parses_a_well_formed_response():
    raw = (
        '{"mappings": [{"control_id": "ia-2.1", "relationship": "satisfies",'
        ' "confidence": 0.9, "rationale": "MFA for privileged access."}]}'
    )
    out = parse_crosswalk_response(raw)
    assert out[0]["control_id"] == "ia-2.1"
    assert out[0]["confidence"] == 0.9


def test_parses_a_bare_array_response():
    """Models sometimes return the array without the wrapper object."""
    raw = '[{"control_id": "cm-7", "relationship": "supports", "confidence": 0.5}]'
    assert parse_crosswalk_response(raw)[0]["control_id"] == "cm-7"


def test_parses_a_response_wrapped_in_markdown_fences():
    raw = '```json\n{"mappings": [{"control_id": "cm-7"}]}\n```'
    assert parse_crosswalk_response(raw)[0]["control_id"] == "cm-7"


def test_malformed_json_yields_no_mappings_rather_than_raising():
    """A bad reply must degrade to 'no AI enrichment', never break the run."""
    assert parse_crosswalk_response("I'm afraid I can't do that") == []


def test_empty_response_yields_no_mappings():
    assert parse_crosswalk_response("") == []


# ------------------------------------------------- OpenAI-compatible backend
# Foundry serverless deployments (Phi, Mistral) and GitHub Models are reached
# with a plain base_url, not Azure OpenAI's deployment-routed URLs. Both shapes
# are supported so whichever a subscription can actually provision will work.

GENERIC_VARS = ("MODEL_ENDPOINT", "MODEL_API_KEY", "MODEL_NAME")


def _clear_all(monkeypatch):
    for var in ENV_VARS + GENERIC_VARS:
        monkeypatch.delenv(var, raising=False)


def test_generic_credentials_alone_are_enough(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("MODEL_ENDPOINT", "https://r.services.ai.azure.com/models")
    monkeypatch.setenv("MODEL_API_KEY", "key")
    monkeypatch.setenv("MODEL_NAME", "Phi-4-mini-instruct")
    assert is_configured() is True


def test_generic_credentials_select_the_compatible_mode(monkeypatch):
    from regulator.agents.foundry import FoundryConfig

    _clear_all(monkeypatch)
    monkeypatch.setenv("MODEL_ENDPOINT", "https://r.services.ai.azure.com/models")
    monkeypatch.setenv("MODEL_API_KEY", "key")
    monkeypatch.setenv("MODEL_NAME", "Phi-4-mini-instruct")
    config = FoundryConfig.from_env()
    assert config.mode == "openai-compatible"
    assert config.deployment == "Phi-4-mini-instruct"


def test_azure_credentials_take_precedence(monkeypatch):
    """A real Azure OpenAI deployment is the preferred path when both exist."""
    from regulator.agents.foundry import FoundryConfig

    _clear_all(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "k")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    monkeypatch.setenv("MODEL_ENDPOINT", "https://r.services.ai.azure.com/models")
    monkeypatch.setenv("MODEL_API_KEY", "key")
    monkeypatch.setenv("MODEL_NAME", "Phi-4-mini-instruct")
    assert FoundryConfig.from_env().mode == "azure"


def test_partial_generic_credentials_are_not_enough(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("MODEL_ENDPOINT", "https://r.services.ai.azure.com/models")
    assert is_configured() is False


def test_registry_reports_the_deployment_in_use(monkeypatch, catalog):
    _clear_all(monkeypatch)
    monkeypatch.setenv("MODEL_ENDPOINT", "https://r.services.ai.azure.com/models")
    monkeypatch.setenv("MODEL_API_KEY", "key")
    monkeypatch.setenv("MODEL_NAME", "Phi-4-mini-instruct")
    providers = build_providers(catalog)
    assert providers.backend == "foundry"
    assert "Phi-4-mini-instruct" in providers.describe()
