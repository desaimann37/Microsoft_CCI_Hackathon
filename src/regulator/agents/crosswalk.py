"""The crosswalk engine.

Mapping a SCuBA policy onto NIST SP 800-53 is the project's central piece of
reasoning, and it is genuinely hard: the two frameworks are written at different
altitudes. SCuBA says "legacy authentication SHALL be blocked" - specific,
product-bound. 800-53 says "implement multifactor authentication for privileged
access" - general, outcome-framed. Deciding the first is evidence toward the
second needs an understanding of both the technology and the control's intent.

The engine does not do that reasoning. A provider does. The engine's job is to
make the provider's output *safe*:

* every proposed control ID is checked against the real catalog, so an invented
  reference cannot reach an artifact;
* relationships are forced into a closed vocabulary, so "satisfies" cannot be
  claimed by accident;
* confidence is clamped and surfaced rather than hidden;
* malformed output degrades to no mapping rather than a crash.

CISA publishes its own hand-authored mapping inside the baseline. That is kept
strictly separate - it is authoritative ground truth used to *measure* the
provider, never blended into its output.
"""

from __future__ import annotations

from typing import Any

from ..families import likely_families
from ..models import ControlMapping, ScubaPolicy
from ..nist_catalog import NistCatalog
from .base import CrosswalkProvider

#: Closed vocabulary. Overclaiming is how compliance automation earns its bad
#: reputation, so the difference between these is explicit and enforced.
RELATIONSHIPS = ("satisfies", "supports", "related")

DEFAULT_RELATIONSHIP = "related"

#: Below this, a mapping is held back for human review rather than asserted.
REVIEW_THRESHOLD = 0.35


class CrosswalkEngine:
    """Validates and normalises crosswalk suggestions from a provider."""

    def __init__(
        self,
        catalog: NistCatalog,
        provider: CrosswalkProvider,
        *,
        candidate_limit: int = 24,
    ) -> None:
        self.catalog = catalog
        self.provider = provider
        self.candidate_limit = candidate_limit

    def candidates_for(self, policy: ScubaPolicy) -> list[str]:
        """The controls the provider is allowed to choose among.

        Blends lexical retrieval with the families the policy's subject matter
        implies, so the right answer is actually on the menu.
        """
        text = f"{policy.requirement} {policy.rationale or ''}"
        return self.catalog.search(
            text, limit=self.candidate_limit, families=likely_families(text)
        )

    def map_policy(self, policy: ScubaPolicy) -> list[ControlMapping]:
        """Return validated mappings for one SCuBA policy."""
        candidates = self.candidates_for(policy)

        try:
            raw = self.provider.propose(policy, candidates)
        except Exception:
            # A provider failure must not take down the pipeline. The
            # deterministic artifacts are still correct without AI enrichment.
            return []

        best: dict[str, ControlMapping] = {}
        for suggestion in raw or []:
            mapping = self._coerce(policy, suggestion)
            if mapping is None:
                continue
            existing = best.get(mapping.control_id)
            if existing is None or mapping.confidence > existing.confidence:
                best[mapping.control_id] = mapping

        return sorted(best.values(), key=lambda m: (-m.confidence, m.control_id))

    def cisa_mapping(self, policy: ScubaPolicy) -> list[str]:
        """CISA's own published mapping, resolved to catalog control IDs.

        This is ground truth for evaluation. It is never returned as, or mixed
        into, AI output.
        """
        resolved = []
        for reference in policy.nist_controls:
            control_id = self.catalog.resolve(reference)
            if control_id and control_id not in resolved:
                resolved.append(control_id)
        return resolved

    # ------------------------------------------------------------- internals

    def _coerce(
        self, policy: ScubaPolicy, suggestion: Any
    ) -> ControlMapping | None:
        """Turn one raw suggestion into a validated mapping, or None."""
        if not isinstance(suggestion, dict):
            return None

        raw_id = suggestion.get("control_id")
        if not isinstance(raw_id, str):
            return None

        # Accept either a catalog ID or a human reference like "IA-2(1)".
        control_id = raw_id.strip().lower()
        if not self.catalog.exists(control_id):
            control_id = self.catalog.resolve(raw_id) or ""
        if not control_id or not self.catalog.exists(control_id):
            return None  # invented, or unresolvable - discarded

        relationship = suggestion.get("relationship")
        if relationship not in RELATIONSHIPS:
            relationship = DEFAULT_RELATIONSHIP

        try:
            confidence = float(suggestion.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        rationale = str(suggestion.get("rationale") or "").strip()
        if not rationale:
            rationale = (
                f"Proposed as evidence toward {control_id} "
                f"({self.catalog.title(control_id)})."
            )

        return ControlMapping(
            policy_id=policy.id,
            control_id=control_id,
            relationship=relationship,
            confidence=confidence,
            rationale=rationale,
            source="ai",
        )
