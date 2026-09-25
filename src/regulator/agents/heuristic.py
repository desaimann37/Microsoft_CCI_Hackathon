"""Offline providers: no credentials, no network, fully deterministic.

These exist for two reasons, and the second is the important one.

1. The pipeline must run end to end without Azure access, so the deterministic
   core is always testable and the system is reproducible by anyone who clones
   the repository.

2. **They are a baseline to beat.** The crosswalk provider here deliberately
   does *not* look at CISA's published mapping - it works from lexical evidence
   against the real 800-53 catalog. That keeps evaluation honest: measuring a
   provider against ground truth it was handed would report perfect accuracy and
   mean nothing. Whatever the Foundry provider scores, it has to beat this.
"""

from __future__ import annotations

from typing import Any

from ..models import PolicyResult, ScubaPolicy
from ..nist_catalog import NistCatalog

#: Domain hints from SCuBA vocabulary to 800-53 control families. These encode
#: what a practitioner knows, not what CISA published.
FAMILY_HINTS: dict[str, tuple[str, ...]] = {
    "ia": ("authentication", "mfa", "multifactor", "phishing", "password",
           "credential", "identity", "sign-in", "login", "passkey", "fido"),
    "ac": ("access", "role", "privilege", "administrator", "admin", "consent",
           "guest", "permission", "account", "session"),
    "au": ("log", "logging", "audit", "monitor", "alert", "event"),
    "cm": ("configuration", "setting", "legacy", "protocol", "baseline",
           "disable", "block", "restrict"),
    "si": ("malware", "threat", "risk", "detection", "integrity", "spam"),
    "sc": ("encryption", "tls", "certificate", "boundary", "transmission"),
    "at": ("training", "awareness"),
    "ir": ("incident", "response"),
}

_RELATIONSHIP_BY_SCORE = ((0.62, "satisfies"), (0.38, "supports"))


class HeuristicProvider:
    """Lexical crosswalk baseline over the real 800-53 catalog."""

    def __init__(self, catalog: NistCatalog, *, max_mappings: int = 5) -> None:
        self.catalog = catalog
        self.max_mappings = max_mappings

    def propose(
        self, policy: ScubaPolicy, candidates: list[str]
    ) -> list[dict[str, Any]]:
        text = f"{policy.requirement} {policy.rationale or ''}".lower()
        families = self._likely_families(text)

        scored: list[tuple[float, str]] = []
        for rank, control_id in enumerate(candidates):
            # Retrieval rank carries most of the signal; family agreement
            # sharpens it toward the right corner of the catalog.
            base = 1.0 - (rank / max(len(candidates), 1))
            if self.catalog.family(control_id) in families:
                base = min(1.0, base + 0.25)
            scored.append((round(base, 3), control_id))

        scored.sort(key=lambda pair: (-pair[0], pair[1]))

        out: list[dict[str, Any]] = []
        for score, control_id in scored[: self.max_mappings]:
            out.append(
                {
                    "control_id": control_id,
                    "relationship": _relationship(score),
                    "confidence": score,
                    "rationale": (
                        f"Lexical and control-family evidence links "
                        f"'{policy.requirement}' to {control_id.upper()} "
                        f"({self.catalog.title(control_id)})."
                    ),
                }
            )
        return out

    def _likely_families(self, text: str) -> set[str]:
        return {
            family
            for family, keywords in FAMILY_HINTS.items()
            if any(k in text for k in keywords)
        }


class HeuristicRiskProvider:
    """Ranks failures without a model: criticality, mandate, and blast radius."""

    #: Vocabulary that indicates a failure reaches the whole tenant.
    TENANT_WIDE = (
        "legacy authentication", "global administrator", "privileged",
        "all users", "mfa", "multifactor", "phishing-resistant", "consent",
    )

    def rank(
        self, failures: list[PolicyResult], policies: dict[str, ScubaPolicy]
    ) -> list[dict[str, Any]]:
        scored = []
        for failure in failures:
            policy = policies.get(failure.policy_id)
            text = (policy.requirement if policy else failure.details).lower()

            score = 0.0
            if policy and policy.criticality == "SHALL":
                score += 2.0
            if policy and policy.bod_25_01:
                score += 1.5
            tenant_wide = any(term in text for term in self.TENANT_WIDE)
            if tenant_wide:
                score += 2.0
            # A failure that disables a preventive control compounds others.
            if policy and policy.mitre_techniques:
                score += 0.5 * min(len(policy.mitre_techniques), 4)

            scored.append((score, failure, policy, tenant_wide))

        scored.sort(key=lambda item: (-item[0], item[1].policy_id))

        out = []
        for rank, (score, failure, policy, tenant_wide) in enumerate(scored, 1):
            out.append(
                {
                    "policy_id": failure.policy_id,
                    "severity": _severity(score),
                    "blast_radius": "tenant-wide" if tenant_wide else "scoped",
                    "exploitability": (
                        "remote" if tenant_wide else "requires-local-context"
                    ),
                    "reasoning": _risk_reasoning(policy, tenant_wide),
                    "rank": rank,
                }
            )
        return out


class HeuristicRemediationProvider:
    """Templated remediation grounded in the policy's own requirement text."""

    EFFORT_BY_CRITICALITY = {"SHALL": "medium", "SHOULD": "low"}

    def draft(
        self, failure: PolicyResult, policy: ScubaPolicy | None
    ) -> dict[str, Any]:
        requirement = policy.requirement if policy else failure.details
        section = policy.group_name if policy else "the relevant baseline section"

        steps = [
            f"Review the current tenant configuration for {failure.policy_id} "
            f"in the Microsoft 365 admin centre.",
            f"Apply the change required to satisfy: {requirement}",
            f"Consult the CISA SCuBA implementation guidance for '{section}' "
            f"before enforcing, and check sign-in logs for dependent clients.",
            f"Re-run ScubaGear and confirm {failure.policy_id} reports Pass.",
        ]
        criticality = policy.criticality if policy else "SHALL"
        return {
            "policy_id": failure.policy_id,
            "steps": steps,
            "effort": self.EFFORT_BY_CRITICALITY.get(criticality, "medium"),
            "owner_role": "Identity Administrator",
            "target_days": 30 if criticality == "SHALL" else 90,
        }


class HeuristicQueryProvider:
    """Retrieval-only answering over the generated artifacts.

    Honest about what it is: it quotes the structured data rather than
    generating prose about it. With a Foundry provider configured, the same
    context is handed to a model instead.
    """

    def answer(self, question: str, context: str) -> dict[str, Any]:
        terms = [t for t in question.lower().split() if len(t) > 3]
        # Only data rows are quotable. Section headers match query words easily
        # ("which controls failed?" matches "FAILING CONTROLS") and would
        # otherwise crowd out the findings the question is actually about.
        lines = [ln for ln in context.splitlines() if ln.strip().startswith("- ")]
        hits = [ln for ln in lines if any(t in ln.lower() for t in terms)]
        selected = hits[:12] or lines[:12]

        citations = []
        for line in selected:
            for token in line.replace("(", " ").replace(")", " ").split():
                if token.upper().startswith("MS.AAD.") and token not in citations:
                    citations.append(token.strip(".,:"))

        if not selected:
            return {
                "answer": "The generated artifacts do not contain an answer to "
                          "that question.",
                "citations": [],
            }

        body = "\n".join(f"- {line.strip()}" for line in selected)
        return {
            "answer": (
                "Answering directly from the validated OSCAL artifacts "
                "(retrieval only - no model configured):\n" + body
            ),
            "citations": citations[:12],
        }


def _relationship(score: float) -> str:
    for threshold, relationship in _RELATIONSHIP_BY_SCORE:
        if score >= threshold:
            return relationship
    return "related"


def _severity(score: float) -> str:
    if score >= 5.5:
        return "critical"
    if score >= 4.0:
        return "high"
    if score >= 2.5:
        return "moderate"
    return "low"


def _risk_reasoning(policy: ScubaPolicy | None, tenant_wide: bool) -> str:
    if policy is None:
        return "Control failed; no baseline text available for this policy."
    parts = [policy.rationale or f"{policy.id} is not satisfied."]
    if tenant_wide:
        parts.append(
            "This failure affects authentication or privilege across the whole "
            "tenant rather than a single feature, so its blast radius is wide."
        )
    if policy.bod_25_01:
        parts.append("This policy is mandatory under CISA BOD 25-01.")
    return " ".join(parts)
