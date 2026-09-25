"""Microsoft Foundry providers.

Model deployments on Foundry are consumed through the Azure OpenAI-compatible
API, so this module talks to that endpoint. The network call is deliberately
thin; the parts that carry correctness - prompt assembly and response parsing -
are pure functions that can be tested without credentials.

Two design decisions are load-bearing:

**The model never sees CISA's answer.** CISA's published SP 800-53 mapping is
the ground truth the crosswalk is measured against. Including it in the prompt
would produce a flattering score that meant nothing, so the prompt carries only
retrieved candidate controls.

**The model never emits OSCAL.** It returns small typed judgements, which the
engines validate and the renderers place into documents. A model that returns
nonsense costs the run its AI enrichment; it cannot produce an invalid artifact.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

from ..models import PolicyResult, ScubaPolicy
from ..nist_catalog import NistCatalog

DEFAULT_API_VERSION = "2024-10-21"
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)

SYSTEM_PROMPT = (
    "You are a federal compliance analyst mapping CISA SCuBA cloud security "
    "policies onto NIST SP 800-53 Rev 5 controls.\n"
    "Rules you must follow:\n"
    "- Choose ONLY from the candidate controls supplied. Never invent an ID.\n"
    "- Prefer precision over coverage. An unsupportable mapping is worse than "
    "a missing one.\n"
    "- Use 'satisfies' only when the SCuBA policy fully meets the control's "
    "intent; 'supports' when it contributes partial evidence; 'related' when "
    "the connection is contextual.\n"
    "- Give an honest confidence. Low confidence is useful information.\n"
    "Respond with JSON only."
)


@dataclass(frozen=True)
class FoundryConfig:
    """How to reach the model.

    Foundry exposes deployments two ways, and which one a subscription can
    actually provision varies by region and quota:

    ``azure``
        Azure OpenAI deployment-routed URLs
        (``/openai/deployments/<name>/chat/completions``). Used by Global
        Standard deployments of gpt-4o, Phi-4 and similar.
    ``openai-compatible``
        A plain ``base_url``, used by Foundry serverless endpoints, GitHub
        Models, and other OpenAI-compatible gateways.

    Supporting both means whichever one a given subscription can provision
    will work without code changes.
    """

    endpoint: str
    api_key: str
    deployment: str
    api_version: str = DEFAULT_API_VERSION
    mode: str = "azure"

    @classmethod
    def from_env(cls) -> FoundryConfig | None:
        api_version = (
            os.getenv("AZURE_OPENAI_API_VERSION", DEFAULT_API_VERSION).strip()
            or DEFAULT_API_VERSION
        )

        # A real Azure OpenAI deployment is preferred when both are configured.
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()
        api_key = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip()
        if endpoint and api_key and deployment:
            return cls(
                endpoint=endpoint,
                api_key=api_key,
                deployment=deployment,
                api_version=api_version,
                mode="azure",
            )

        endpoint = os.getenv("MODEL_ENDPOINT", "").strip()
        api_key = os.getenv("MODEL_API_KEY", "").strip()
        model = os.getenv("MODEL_NAME", "").strip()
        if endpoint and api_key and model:
            return cls(
                endpoint=endpoint,
                api_key=api_key,
                deployment=model,
                api_version=api_version,
                mode="openai-compatible",
            )
        return None


def is_configured() -> bool:
    """True when every credential a Foundry call needs is present."""
    return FoundryConfig.from_env() is not None


# --------------------------------------------------------------- prompting


def build_crosswalk_prompt(
    policy: ScubaPolicy, candidates: list[str], catalog: NistCatalog
) -> str:
    """Assemble the crosswalk prompt.

    Only retrieved candidates appear. CISA's own mapping is withheld so that
    evaluation against it stays meaningful.
    """
    lines = [
        f"SCuBA policy {policy.id} ({policy.criticality}) from the "
        f"'{policy.group_name}' section of the "
        f"Microsoft {policy.id.split('.')[1]} baseline.",
        "",
        f"Requirement: {policy.requirement}",
    ]
    if policy.rationale:
        lines.append(f"Rationale: {policy.rationale}")

    lines += ["", "Candidate NIST SP 800-53 Rev 5 controls:"]
    for control_id in candidates:
        text = catalog.text(control_id)
        lines.append(f"- {control_id}: {text[:400]}")

    lines += [
        "",
        "Which candidates does this policy provide evidence toward?",
        "Return JSON: {\"mappings\": [{\"control_id\": \"<one of the "
        "candidates>\", \"relationship\": \"satisfies|supports|related\", "
        "\"confidence\": 0.0-1.0, \"rationale\": \"<one sentence>\"}]}",
        "Return an empty mappings array if none genuinely apply.",
    ]
    return "\n".join(lines)


def parse_crosswalk_response(raw: str) -> list[dict[str, Any]]:
    """Parse a model reply into raw suggestions, tolerating its habits.

    Handles the object form, a bare array, and markdown code fences. Anything
    unparseable yields no mappings - the run continues without AI enrichment
    rather than failing.
    """
    if not raw or not raw.strip():
        return []

    text = raw.strip()
    if match := _FENCE_RE.search(text):
        text = match.group(1).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        mappings = data.get("mappings")
        if isinstance(mappings, list):
            return [d for d in mappings if isinstance(d, dict)]
    return []


# --------------------------------------------------------------- providers


class _FoundryClient:
    """Lazily constructed Azure OpenAI client."""

    def __init__(self, config: FoundryConfig) -> None:
        self.config = config
        self._client = None

    def _build(self):
        if self.config.mode == "azure":
            from openai import AzureOpenAI

            return AzureOpenAI(
                azure_endpoint=self.config.endpoint,
                api_key=self.config.api_key,
                api_version=self.config.api_version,
            )
        from openai import OpenAI

        return OpenAI(
            base_url=self.config.endpoint,
            api_key=self.config.api_key,
        )

    def complete(self, system: str, user: str, *, max_tokens: int = 1200) -> str:
        if self._client is None:
            self._client = self._build()

        kwargs = {
            "model": self.config.deployment,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,  # reproducibility matters for an audit artifact
            "max_tokens": max_tokens,
        }

        try:
            response = self._client.chat.completions.create(
                **kwargs, response_format={"type": "json_object"}
            )
        except Exception:
            # Not every model on Foundry supports JSON mode - the smaller Phi
            # deployments in particular. The parsers already tolerate fenced and
            # bare JSON, so falling back costs robustness, not correctness.
            response = self._client.chat.completions.create(**kwargs)

        return response.choices[0].message.content or ""


class FoundryProvider:
    """Crosswalk provider backed by a Foundry model deployment."""

    def __init__(self, catalog: NistCatalog, config: FoundryConfig) -> None:
        self.catalog = catalog
        self.client = _FoundryClient(config)

    def propose(
        self, policy: ScubaPolicy, candidates: list[str]
    ) -> list[dict[str, Any]]:
        if not candidates:
            return []
        prompt = build_crosswalk_prompt(policy, candidates, self.catalog)
        return parse_crosswalk_response(self.client.complete(SYSTEM_PROMPT, prompt))


class FoundryRiskProvider:
    """Ranks the whole failure set at once, so interactions are visible."""

    SYSTEM = (
        "You are a cloud security analyst triaging failed CISA SCuBA checks in "
        "a Microsoft 365 tenant. Rank by real-world danger, not by label. "
        "Consider blast radius and how failures compound - a control that "
        "nullifies MFA tenant-wide outranks one affecting a single feature. "
        "Respond with JSON only."
    )

    def __init__(self, config: FoundryConfig) -> None:
        self.client = _FoundryClient(config)

    def rank(
        self, failures: list[PolicyResult], policies: dict[str, ScubaPolicy]
    ) -> list[dict[str, Any]]:
        if not failures:
            return []
        lines = ["Failed controls in this tenant:", ""]
        for failure in failures:
            policy = policies.get(failure.policy_id)
            lines.append(
                f"- {failure.policy_id}: "
                f"{policy.requirement if policy else failure.details}"
            )
        lines += [
            "",
            "Rank every one of them. Return JSON: {\"risks\": [{\"policy_id\": "
            "\"...\", \"severity\": \"critical|high|moderate|low\", "
            "\"blast_radius\": \"...\", \"exploitability\": \"...\", "
            "\"reasoning\": \"...\", \"rank\": 1}]}",
        ]
        raw = self.client.complete(self.SYSTEM, "\n".join(lines), max_tokens=2500)
        return _parse_list(raw, "risks")


class FoundryRemediationProvider:
    SYSTEM = (
        "You write remediation steps for Microsoft 365 security "
        "misconfigurations. Be specific to the setting that failed and write "
        "for the administrator who will act on it. Ground every step in real "
        "Microsoft 365 administration. Respond with JSON only."
    )

    def __init__(self, config: FoundryConfig) -> None:
        self.client = _FoundryClient(config)

    def draft(
        self, failure: PolicyResult, policy: ScubaPolicy | None
    ) -> dict[str, Any]:
        requirement = policy.requirement if policy else failure.details
        prompt = (
            f"Control {failure.policy_id} failed.\n"
            f"Requirement: {requirement}\n"
            f"Tool detail: {failure.details}\n\n"
            "Return JSON: {\"steps\": [\"...\"], \"effort\": "
            "\"low|medium|high\", \"owner_role\": \"...\", \"target_days\": 30}"
        )
        try:
            data = json.loads(self.client.complete(self.SYSTEM, prompt) or "{}")
        except json.JSONDecodeError:
            return {}
        data["policy_id"] = failure.policy_id
        return data


class FoundryQueryProvider:
    SYSTEM = (
        "You answer questions about a Microsoft 365 tenant's CISA SCuBA "
        "compliance posture, using ONLY the OSCAL artifact extract provided. "
        "Every factual claim must cite the SCuBA policy ID it rests on. If the "
        "extract does not answer the question, say so plainly rather than "
        "inferring. Respond with JSON only."
    )

    def __init__(self, config: FoundryConfig) -> None:
        self.client = _FoundryClient(config)

    def answer(self, question: str, context: str) -> dict[str, Any]:
        prompt = (
            f"Question: {question}\n\nArtifact extract:\n{context}\n\n"
            "Return JSON: {\"answer\": \"...\", \"citations\": "
            "[\"MS.AAD.1.1v1\"]}"
        )
        try:
            data = json.loads(
                self.client.complete(self.SYSTEM, prompt, max_tokens=1500) or "{}"
            )
        except json.JSONDecodeError:
            return {"answer": "", "citations": []}
        return {
            "answer": str(data.get("answer", "")),
            "citations": [str(c) for c in data.get("citations", [])],
        }


def _parse_list(raw: str, key: str) -> list[dict[str, Any]]:
    if not raw:
        return []
    text = raw.strip()
    if match := _FENCE_RE.search(text):
        text = match.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    items = data.get(key) if isinstance(data, dict) else None
    return [d for d in items if isinstance(d, dict)] if isinstance(items, list) else []
