"""Provider selection.

One decision, made in one place: use Microsoft Foundry when it is configured,
fall back to the offline heuristics when it is not. Nothing downstream knows or
cares which backend it got, which is what lets the pipeline run identically in
CI, on a laptop with no Azure access, and in a live demo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..nist_catalog import NistCatalog
from . import foundry as foundry_mod
from .heuristic import (
    HeuristicProvider,
    HeuristicQueryProvider,
    HeuristicRemediationProvider,
    HeuristicRiskProvider,
)


@dataclass(frozen=True)
class Providers:
    """The four agents, plus which backend supplied them."""

    backend: str  # "foundry" | "heuristic"
    crosswalk: Any
    risk: Any
    remediation: Any
    query: Any

    @property
    def is_ai_backed(self) -> bool:
        return self.backend == "foundry"

    def describe(self) -> str:
        if self.is_ai_backed:
            config = foundry_mod.FoundryConfig.from_env()
            deployment = config.deployment if config else "unknown"
            return f"Microsoft Foundry (deployment: {deployment})"
        return "offline heuristics (no Foundry credentials configured)"


def build_providers(catalog: NistCatalog) -> Providers:
    """Return Foundry-backed providers if configured, heuristics otherwise."""
    config = foundry_mod.FoundryConfig.from_env()
    if config is None:
        return Providers(
            backend="heuristic",
            crosswalk=HeuristicProvider(catalog),
            risk=HeuristicRiskProvider(),
            remediation=HeuristicRemediationProvider(),
            query=HeuristicQueryProvider(),
        )
    return Providers(
        backend="foundry",
        crosswalk=foundry_mod.FoundryProvider(catalog, config),
        risk=foundry_mod.FoundryRiskProvider(config),
        remediation=foundry_mod.FoundryRemediationProvider(config),
        query=foundry_mod.FoundryQueryProvider(config),
    )
