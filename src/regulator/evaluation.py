"""Measuring the crosswalk against CISA's published mapping.

The claim "our AI works" is worth very little without a number behind it. CISA
authored an SP 800-53 mapping for each SCuBA policy and published it inside the
baseline document, which gives this project something most entries will not
have: an authoritative reference set covering every policy, produced by the
authority itself rather than by us.

Both a strict and a forgiving score are always reported. Exact matching treats
``ia-2`` as entirely wrong when CISA wrote ``ia-2(1)``; family matching gives
partial credit for what a reviewer would call "basically right". Publishing only
the flattering figure would be dishonest, so both travel together.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .agents.crosswalk import CrosswalkEngine
from .models import ScubaBaseline


@dataclass(frozen=True)
class Score:
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyScore:
    policy_id: str
    predicted: list[str]
    truth: list[str]
    exact_hits: list[str]
    family_hits: list[str]

    @property
    def has_exact_hit(self) -> bool:
        return bool(self.exact_hits)

    @property
    def has_family_hit(self) -> bool:
        return bool(self.family_hits)


@dataclass
class CrosswalkReport:
    provider: str
    policies_evaluated: int
    exact: Score
    family: Score
    exact_hit_rate: float
    family_hit_rate: float
    per_policy: list[PolicyScore] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "policies_evaluated": self.policies_evaluated,
            "exact": self.exact.to_dict(),
            "family": self.family.to_dict(),
            "exact_hit_rate": self.exact_hit_rate,
            "family_hit_rate": self.family_hit_rate,
            "per_policy": [asdict(p) for p in self.per_policy],
        }

    def summary(self) -> str:
        return (
            f"{self.provider} over {self.policies_evaluated} policies with "
            f"CISA ground truth:\n"
            f"  exact   P={self.exact.precision:.2f} R={self.exact.recall:.2f} "
            f"F1={self.exact.f1:.2f}  hit-rate={self.exact_hit_rate:.0%}\n"
            f"  family  P={self.family.precision:.2f} R={self.family.recall:.2f} "
            f"F1={self.family.f1:.2f}  hit-rate={self.family_hit_rate:.0%}"
        )


def score_sets(predicted: set[str], truth: set[str]) -> Score:
    """Precision, recall and F1 for one prediction against one truth set."""
    if not predicted or not truth:
        return Score(0.0, 0.0, 0.0)
    hits = predicted & truth
    precision = len(hits) / len(predicted)
    recall = len(hits) / len(truth)
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return Score(precision, recall, f1)


def evaluate_crosswalk(
    engine: CrosswalkEngine,
    baseline: ScubaBaseline,
    *,
    min_confidence: float = 0.0,
) -> CrosswalkReport:
    """Score a crosswalk engine against CISA's published mapping.

    Only policies for which CISA published a mapping are evaluated - scoring a
    prediction against an absent reference would be meaningless.
    """
    rows: list[PolicyScore] = []

    # Micro-averaged: pool every prediction and every truth across policies, so
    # a policy with eight mapped controls counts more than one with a single
    # control. Macro-averaging would let trivial policies dominate the headline.
    exact_pred = exact_truth = exact_hit = 0
    fam_pred = fam_truth = fam_hit = 0

    for policy in baseline.policies:
        truth = set(engine.cisa_mapping(policy))
        if not truth:
            continue

        predicted = {
            m.control_id
            for m in engine.map_policy(policy)
            if m.confidence >= min_confidence
        }

        exact_hits = predicted & truth
        pred_fams = {_family(c) for c in predicted}
        truth_fams = {_family(c) for c in truth}
        family_hits = pred_fams & truth_fams

        exact_pred += len(predicted)
        exact_truth += len(truth)
        exact_hit += len(exact_hits)

        fam_pred += len(pred_fams)
        fam_truth += len(truth_fams)
        fam_hit += len(family_hits)

        rows.append(
            PolicyScore(
                policy_id=policy.id,
                predicted=sorted(predicted),
                truth=sorted(truth),
                exact_hits=sorted(exact_hits),
                family_hits=sorted(family_hits),
            )
        )

    return CrosswalkReport(
        provider=type(engine.provider).__name__,
        policies_evaluated=len(rows),
        exact=_micro(exact_hit, exact_pred, exact_truth),
        family=_micro(fam_hit, fam_pred, fam_truth),
        exact_hit_rate=_rate(r.has_exact_hit for r in rows),
        family_hit_rate=_rate(r.has_family_hit for r in rows),
        per_policy=rows,
    )


def _micro(hits: int, predicted: int, truth: int) -> Score:
    precision = hits / predicted if predicted else 0.0
    recall = hits / truth if truth else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return Score(precision, recall, f1)


def _rate(flags) -> float:
    values = list(flags)
    return (sum(values) / len(values)) if values else 0.0


def _family(control_id: str) -> str:
    return control_id.split("-", 1)[0]
