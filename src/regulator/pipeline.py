"""The end-to-end pipeline.

    SCuBA baseline ──┐
                     ├──▶ parse ──▶ AI judgements ──▶ render ──▶ VALIDATE ──▶ disk
    ScubaGear JSON ──┘

The ordering is deliberate. Deterministic parsing and rendering carry the
structure; the AI layer only contributes judgements, and it sits between the two
rather than around them. Every artifact is validated against its NIST schema as
it is produced, not once at the end - a schema error discovered on the final
evening is the most predictable way to lose a deadline.

If an artifact does not validate, the pipeline raises. In a compliance tool a
loud failure is correct behaviour; a quiet wrong answer is the worst outcome
available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .agents.crosswalk import CrosswalkEngine
from .agents.registry import Providers, build_providers
from .models import (
    AnalysisBundle,
    Assessment,
    ControlMapping,
    Remediation,
    RiskJudgement,
    ScubaBaseline,
)
from . import paths
from .nist_catalog import load_catalog
from .oscal.assessment_results import build_assessment_results
from .oscal.catalog import build_catalog
from .oscal.component import build_component_definition
from .oscal.poam import build_poam
from .oscal.profile import build_profile
from .parsers.scuba_baseline import parse_baseline
from .parsers.scubagear import parse_assessment
from .validation import ValidationResult, validate

DEFAULT_BASELINE_DIR = paths.BASELINE_DIR
DEFAULT_NIST_CATALOG = str(paths.NIST_CATALOG)

FILENAMES = {
    "catalog": "scuba-catalog-{product}.json",
    "profile": "scuba-profile-{product}.json",
    "component-definition": "component-definition-{product}.json",
    "assessment-results": "assessment-results-{product}.json",
    "poam": "poam-{product}.json",
}


@dataclass
class PipelineRun:
    """Everything one run produced."""

    product: str
    backend: str
    artifacts: dict[str, dict[str, Any]]
    validation: dict[str, ValidationResult]
    written: dict[str, Path]
    summary: dict[str, int]
    analysis: AnalysisBundle
    assessment: Assessment
    baseline: ScubaBaseline
    warnings: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return all(r.valid for r in self.validation.values())


class Pipeline:
    """Turns SCuBA sources plus a ScubaGear report into validated OSCAL."""

    def __init__(
        self,
        *,
        baseline_dir: str | Path = DEFAULT_BASELINE_DIR,
        nist_catalog_path: str = DEFAULT_NIST_CATALOG,
        providers: Providers | None = None,
    ) -> None:
        self.baseline_dir = Path(baseline_dir)
        self.nist_catalog_path = nist_catalog_path
        self._providers = providers

    def providers(self) -> Providers:
        if self._providers is None:
            self._providers = build_providers(load_catalog(self.nist_catalog_path))
        return self._providers

    def run(
        self,
        scubagear_path: str | Path,
        *,
        product: str = "AAD",
        output_dir: str | Path,
        last_modified: datetime | None = None,
    ) -> PipelineRun:
        """Execute the full pipeline and write artifacts to ``output_dir``."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        baseline_path = self.baseline_dir / f"{product.lower()}.md"
        if not baseline_path.exists():
            raise FileNotFoundError(
                f"no SCuBA baseline for product {product!r} at {baseline_path}"
            )

        baseline = parse_baseline(baseline_path)
        assessment = parse_assessment(scubagear_path, product=product)

        # Reproducibility: the artifact timestamp comes from the assessment, not
        # the wall clock, so re-running over the same report is byte-identical.
        stamp = last_modified or assessment.timestamp.astimezone(timezone.utc)

        warnings = self._check_version_skew(baseline, assessment)
        analysis = self._analyse(baseline, assessment)

        catalog_name = FILENAMES["catalog"].format(product=product.lower())
        artifacts: dict[str, dict[str, Any]] = {}
        artifacts["catalog"] = build_catalog(baseline, last_modified=stamp)
        artifacts["profile"] = build_profile(
            baseline, catalog_href=catalog_name, last_modified=stamp
        )
        artifacts["component-definition"] = build_component_definition(
            baseline, catalog_href=catalog_name, last_modified=stamp
        )
        artifacts["assessment-results"] = build_assessment_results(
            assessment,
            baseline,
            catalog_href=catalog_name,
            last_modified=stamp,
            analysis=analysis,
        )
        artifacts["poam"] = build_poam(
            assessment,
            baseline,
            assessment_results=artifacts["assessment-results"],
            last_modified=stamp,
            analysis=analysis,
        )

        # Validate as we go, and refuse to write anything invalid.
        validation: dict[str, ValidationResult] = {}
        for model, document in artifacts.items():
            result = validate(document, model)
            validation[model] = result
            result.raise_if_invalid()

        written: dict[str, Path] = {}
        for model, document in artifacts.items():
            path = output_dir / FILENAMES[model].format(product=product.lower())
            path.write_text(
                _canonical_json(document),
                encoding="utf-8",
            )
            written[model] = path

        return PipelineRun(
            product=product,
            backend=self.providers().backend,
            artifacts=artifacts,
            validation=validation,
            written=written,
            summary=_summarise(assessment),
            analysis=analysis,
            assessment=assessment,
            baseline=baseline,
            warnings=warnings,
        )

    # ------------------------------------------------------------- internals

    def _analyse(
        self, baseline: ScubaBaseline, assessment: Assessment
    ) -> AnalysisBundle:
        """Collect the AI layer's judgements. Failures here are never fatal."""
        providers = self.providers()
        catalog = load_catalog(self.nist_catalog_path)
        bundle = AnalysisBundle()

        engine = CrosswalkEngine(catalog, providers.crosswalk)
        for policy in baseline.policies:
            bundle.mappings.extend(engine.map_policy(policy))

        policies = {p.id: p for p in baseline.policies}
        failures = list(assessment.failures)

        try:
            for raw in providers.risk.rank(failures, policies) or []:
                if judgement := _coerce_risk(raw):
                    bundle.risks.append(judgement)
        except Exception:
            pass

        for failure in failures:
            try:
                raw = providers.remediation.draft(
                    failure, policies.get(failure.policy_id)
                )
            except Exception:
                continue
            if remediation := _coerce_remediation(failure.policy_id, raw):
                bundle.remediations.append(remediation)

        return bundle

    def _check_version_skew(
        self, baseline: ScubaBaseline, assessment: Assessment
    ) -> list[str]:
        """Report policies present in one source but not the other.

        ScubaGear ships its own copy of the baseline, so a report produced by an
        older build can reference a policy set that differs from the baseline
        document on disk. Silently dropping either side would hide real gaps.
        """
        baseline_ids = {p.id for p in baseline.policies}
        assessed_ids = {r.policy_id for r in assessment.results}

        warnings = []
        if unknown := sorted(assessed_ids - baseline_ids):
            warnings.append(
                f"{len(unknown)} assessed policies are absent from the baseline "
                f"document (ScubaGear {assessment.tool_version} version skew): "
                f"{', '.join(unknown[:5])}"
            )
        if unassessed := sorted(baseline_ids - assessed_ids):
            warnings.append(
                f"{len(unassessed)} baseline policies were not assessed: "
                f"{', '.join(unassessed[:5])}"
            )
        return warnings


def _summarise(assessment: Assessment) -> dict[str, int]:
    counts = {"total": len(assessment.results), "pass": 0, "fail": 0,
              "warning": 0, "not_applicable": 0}
    key = {"Pass": "pass", "Fail": "fail", "Warning": "warning",
           "N/A": "not_applicable"}
    for result in assessment.results:
        if bucket := key.get(result.result):
            counts[bucket] += 1
    return counts


def _coerce_risk(raw: dict[str, Any]) -> RiskJudgement | None:
    policy_id = raw.get("policy_id")
    if not isinstance(policy_id, str):
        return None
    try:
        rank = int(raw.get("rank", 0))
    except (TypeError, ValueError):
        rank = 0
    severity = str(raw.get("severity", "moderate")).lower()
    if severity not in {"critical", "high", "moderate", "low"}:
        severity = "moderate"
    return RiskJudgement(
        policy_id=policy_id,
        severity=severity,
        blast_radius=str(raw.get("blast_radius", "unknown")),
        exploitability=str(raw.get("exploitability", "unknown")),
        reasoning=str(raw.get("reasoning", "")),
        rank=rank,
    )


def _coerce_remediation(policy_id: str, raw: dict[str, Any]) -> Remediation | None:
    if not isinstance(raw, dict):
        return None
    steps = raw.get("steps")
    if not isinstance(steps, list) or not steps:
        return None
    effort = str(raw.get("effort", "medium")).lower()
    if effort not in {"low", "medium", "high"}:
        effort = "medium"
    try:
        target_days = int(raw.get("target_days", 30))
    except (TypeError, ValueError):
        target_days = 30
    return Remediation(
        policy_id=policy_id,
        steps=tuple(str(s) for s in steps),
        effort=effort,
        owner_role=str(raw.get("owner_role", "Identity Administrator")),
        target_days=target_days,
    )


def _canonical_json(document: dict[str, Any]) -> str:
    import json

    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


__all__ = [
    "Pipeline",
    "PipelineRun",
    "build_catalog",
    "build_profile",
    "build_component_definition",
    "build_assessment_results",
    "build_poam",
    "ControlMapping",
]
