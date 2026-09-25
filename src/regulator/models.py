"""Regulator's internal domain model.

This sits deliberately between the source formats and OSCAL. Parsers produce it;
renderers consume it. Keeping a neutral model in the middle means the OSCAL
renderers never have to know about markdown quirks or ScubaGear's field names,
and the AI layer reasons over typed objects rather than raw documents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


# --------------------------------------------------------------------------
# Baseline side: what CISA says you must configure
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineGroup:
    """A numbered section of a SCuBA baseline, e.g. '1. Legacy Authentication'."""

    number: str
    name: str


@dataclass(frozen=True)
class ScubaPolicy:
    """A single SCuBA requirement, e.g. MS.AAD.1.1v1."""

    id: str
    requirement: str
    criticality: str  # "SHALL" or "SHOULD"
    group_number: str
    group_name: str
    rationale: str | None = None
    last_modified: str | None = None
    bod_25_01: bool = False
    #: CISA's own hand-authored SP 800-53 mapping (FedRAMP High baseline only).
    #: Used as ground truth when evaluating the crosswalk agent.
    nist_controls: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScubaBaseline:
    product: str  # "AAD", "EXO", ...
    title: str
    groups: tuple[BaselineGroup, ...]
    policies: tuple[ScubaPolicy, ...]

    def policy(self, policy_id: str) -> ScubaPolicy:
        for p in self.policies:
            if p.id == policy_id:
                return p
        raise KeyError(policy_id)


# --------------------------------------------------------------------------
# Assessment side: what ScubaGear found in a real tenant
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyResult:
    """One ScubaGear verdict against one policy."""

    policy_id: str
    result: str  # "Pass" | "Fail" | "Warning" | "N/A"
    criticality: str  # as reported: "Shall", "Should", "Shall/Not-Implemented", ...
    details: str
    group_number: str
    group_name: str

    @property
    def is_failure(self) -> bool:
        return self.result == "Fail"


@dataclass(frozen=True)
class Assessment:
    """A parsed ScubaGear run against one tenant."""

    tenant_id: str
    tenant_name: str
    product: str
    tool: str
    tool_version: str
    timestamp: datetime
    results: tuple[PolicyResult, ...]

    @property
    def failures(self) -> tuple[PolicyResult, ...]:
        return tuple(r for r in self.results if r.is_failure)

    def result(self, policy_id: str) -> PolicyResult:
        for r in self.results:
            if r.policy_id == policy_id:
                return r
        raise KeyError(policy_id)


# --------------------------------------------------------------------------
# AI-derived judgements. Agents return these; code renders them into OSCAL.
# Agents never emit OSCAL directly.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlMapping:
    """A proposed correspondence between a SCuBA policy and an 800-53 control."""

    policy_id: str
    control_id: str
    relationship: str  # "satisfies" | "supports" | "related"
    confidence: float
    rationale: str
    source: str = "ai"  # "cisa" for CISA's published mapping, "ai" for ours


@dataclass(frozen=True)
class RiskJudgement:
    policy_id: str
    severity: str  # "critical" | "high" | "moderate" | "low"
    blast_radius: str
    exploitability: str
    reasoning: str
    rank: int


@dataclass(frozen=True)
class Remediation:
    policy_id: str
    steps: tuple[str, ...]
    effort: str  # "low" | "medium" | "high"
    owner_role: str
    target_days: int


@dataclass
class AnalysisBundle:
    """Everything the AI layer contributed to one assessment."""

    mappings: list[ControlMapping] = field(default_factory=list)
    risks: list[RiskJudgement] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)

    def risk_for(self, policy_id: str) -> RiskJudgement | None:
        return next((r for r in self.risks if r.policy_id == policy_id), None)

    def remediation_for(self, policy_id: str) -> Remediation | None:
        return next((r for r in self.remediations if r.policy_id == policy_id), None)

    def mappings_for(self, policy_id: str) -> list[ControlMapping]:
        return [m for m in self.mappings if m.policy_id == policy_id]
