"""Natural-language querying over the generated OSCAL artifacts.

This is where the format change pays off. Because the assessment is structured
data rather than an HTML report, "what should we fix first, and what does it
cost?" is a question the data can answer - and every claim in the answer can be
traced to the finding it came from.

Citations are enforced, not requested. A policy ID the artifacts do not contain
is stripped from the answer and recorded separately, because an unverifiable
citation inside a compliance answer is worse than none at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .agents.heuristic import HeuristicQueryProvider

_POLICY_RE = re.compile(r"\bMS\.[A-Z0-9]+\.\d+\.\d+v\d+\b")

DEFAULT_MAX_CHARS = 12000


@dataclass
class Answer:
    text: str
    citations: list[str] = field(default_factory=list)
    dropped_citations: list[str] = field(default_factory=list)

    @property
    def is_grounded(self) -> bool:
        return bool(self.citations)


class QueryEngine:
    """Answers questions from an assessment's artifacts."""

    def __init__(
        self,
        *,
        findings: list[dict[str, Any]],
        provider: Any | None = None,
    ) -> None:
        self._findings = findings
        self._provider = provider or HeuristicQueryProvider()
        self._known = {f["policy_id"] for f in findings}

    # ------------------------------------------------------------ construction

    @classmethod
    def from_run(cls, run, provider: Any | None = None) -> QueryEngine:
        """Build a query engine from a completed pipeline run."""
        risks = {r.policy_id: r for r in run.analysis.risks}
        remediations = {r.policy_id: r for r in run.analysis.remediations}
        policies = {p.id: p for p in run.baseline.policies}

        findings = []
        for result in run.assessment.results:
            policy = policies.get(result.policy_id)
            risk = risks.get(result.policy_id)
            remediation = remediations.get(result.policy_id)
            findings.append(
                {
                    "policy_id": result.policy_id,
                    "result": result.result,
                    "section": result.group_name,
                    "requirement": policy.requirement if policy else result.details,
                    "criticality": policy.criticality if policy else "",
                    "bod_25_01": bool(policy.bod_25_01) if policy else False,
                    "severity": risk.severity if risk else "",
                    "rank": risk.rank if risk else 0,
                    "blast_radius": risk.blast_radius if risk else "",
                    "effort": remediation.effort if remediation else "",
                    "owner": remediation.owner_role if remediation else "",
                }
            )
        return cls(findings=findings, provider=provider)

    # -------------------------------------------------------------- behaviour

    def known_policy_ids(self) -> set[str]:
        return set(self._known)

    def context(self, max_chars: int = DEFAULT_MAX_CHARS) -> str:
        """Render the artifacts as compact grounding text.

        Failures come first and are ordered by rank, so that truncation removes
        the least important material rather than an arbitrary tail.
        """
        failures = sorted(
            (f for f in self._findings if f["result"] == "Fail"),
            key=lambda f: (f["rank"] or 999, f["policy_id"]),
        )
        others = [f for f in self._findings if f["result"] != "Fail"]

        lines: list[str] = []
        if failures:
            lines.append("FAILING CONTROLS (highest risk first):")
            lines += [_line(f) for f in failures]
        if others:
            lines.append("")
            lines.append("OTHER RESULTS:")
            lines += [_line(f) for f in others]

        text = "\n".join(lines)
        if len(text) <= max_chars:
            return text
        return text[:max_chars].rsplit("\n", 1)[0]

    def ask(self, question: str, *, max_chars: int = DEFAULT_MAX_CHARS) -> Answer:
        """Answer ``question`` from the artifacts, with verified citations."""
        context = self.context(max_chars=max_chars)
        try:
            raw = self._provider.answer(question, context) or {}
        except Exception as exc:
            return Answer(
                text=(
                    "The query agent is unavailable, so no answer could be "
                    f"produced ({exc}). The validated artifacts are unaffected."
                )
            )

        text = str(raw.get("answer", "")).strip()
        proposed = [str(c).strip() for c in raw.get("citations", []) if str(c).strip()]

        # Anything the model mentioned in prose counts as a claim too.
        proposed += [c for c in _POLICY_RE.findall(text) if c not in proposed]

        kept, dropped = [], []
        for citation in proposed:
            (kept if citation in self._known else dropped).append(citation)

        if not text:
            text = "The artifacts do not contain an answer to that question."

        return Answer(text=text, citations=kept, dropped_citations=dropped)


def _line(finding: dict[str, Any]) -> str:
    bits = [f"{finding['policy_id']} [{finding['result']}]"]
    if finding["severity"]:
        bits.append(f"severity={finding['severity']}")
    if finding["rank"]:
        bits.append(f"rank={finding['rank']}")
    if finding["criticality"]:
        bits.append(finding["criticality"])
    if finding["bod_25_01"]:
        bits.append("BOD-25-01")
    if finding["effort"]:
        bits.append(f"effort={finding['effort']}")
    return f"- {' '.join(bits)} :: {finding['requirement']} ({finding['section']})"
