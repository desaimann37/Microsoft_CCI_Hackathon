"""Provider protocols for the AI layer.

Every agent is defined by a narrow protocol so that a heuristic implementation
and a Microsoft Foundry implementation are interchangeable. Two consequences
matter:

* the deterministic pipeline runs end to end with no credentials and no network,
  which makes the whole system testable and reproducible; and
* the heuristic provider is a genuine *baseline to beat* in evaluation, rather
  than a stub that fakes success.

Providers return plain dictionaries. They never construct OSCAL and never decide
what is valid - the engines above them validate, normalise and score.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..models import PolicyResult, ScubaPolicy


class CrosswalkProvider(Protocol):
    """Proposes NIST SP 800-53 controls for a SCuBA policy."""

    def propose(
        self, policy: ScubaPolicy, candidates: list[str]
    ) -> list[dict[str, Any]]:
        """Return raw suggestions.

        Each suggestion should carry ``control_id``, ``relationship``,
        ``confidence`` and ``rationale``. Malformed entries are discarded
        upstream, so a provider may return anything without breaking the system.
        """
        ...


class RiskProvider(Protocol):
    """Ranks failed findings by the danger they actually represent."""

    def rank(
        self, failures: list[PolicyResult], policies: dict[str, ScubaPolicy]
    ) -> list[dict[str, Any]]:
        """Return one judgement per failure.

        The whole failure set is passed at once, deliberately: the dangerous
        pattern is usually a *combination*, and per-finding scoring would miss
        exactly the insight that makes the ranking worth having.
        """
        ...


class RemediationProvider(Protocol):
    """Drafts remediation guidance for a failed control."""

    def draft(
        self, failure: PolicyResult, policy: ScubaPolicy | None
    ) -> dict[str, Any]:
        ...


class QueryProvider(Protocol):
    """Answers a natural-language question over the generated artifacts."""

    def answer(self, question: str, context: str) -> dict[str, Any]:
        """Return ``{"answer": str, "citations": [str, ...]}``."""
        ...
