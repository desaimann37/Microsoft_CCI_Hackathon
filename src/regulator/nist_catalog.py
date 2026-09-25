"""An index over NIST SP 800-53 Rev 5, which NIST publishes in OSCAL already.

Two jobs:

**Hallucination guard.** Every control identifier an AI agent proposes is
checked here before it is allowed into an artifact. A model that invents
``ia-2.999`` gets its suggestion dropped, so a fabricated control reference is
structurally incapable of reaching an audit document. That guarantee comes from
code, not from prompt wording.

**Grounding.** The crosswalk agent reasons over real control statements
retrieved from this catalog rather than over its own recollection of 800-53.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

_WORD_RE = re.compile(r"[a-z0-9]+")
# "IA-2(1)" -> family ia, number 2, enhancement 1
_REF_RE = re.compile(r"^\s*([A-Za-z]{2})\s*-\s*(\d+)\s*(?:\((\d+)\))?\s*([a-z])?\s*$")

_STOPWORDS = {
    "the", "and", "for", "that", "with", "shall", "must", "are", "not", "any",
    "all", "such", "this", "from", "which", "have", "has", "been", "its", "may",
    "can", "will", "would", "when", "where", "each", "other", "than", "then",
    "system", "organization", "organizational", "information",
}


@dataclass(frozen=True)
class NistControl:
    id: str
    title: str
    text: str
    family: str


class NistCatalog:
    """Read-only index over the SP 800-53 control catalog."""

    def __init__(self, controls: dict[str, NistControl]) -> None:
        self._controls = controls
        self._tokens: dict[str, set[str]] = {
            cid: _tokenise(f"{c.title} {c.text}") for cid, c in controls.items()
        }

    # ---------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: str | Path) -> NistCatalog:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        catalog = raw["catalog"]
        controls: dict[str, NistControl] = {}
        for group in catalog.get("groups", []):
            family = group.get("id", "")
            for control in _walk(group.get("controls", [])):
                cid = control["id"]
                controls[cid] = NistControl(
                    id=cid,
                    title=control.get("title", ""),
                    text=_prose(control),
                    family=family,
                )
        return cls(controls)

    # ------------------------------------------------------------- behaviour

    def __len__(self) -> int:
        return len(self._controls)

    def __contains__(self, control_id: str) -> bool:
        return control_id in self._controls

    def exists(self, control_id: str) -> bool:
        """True if ``control_id`` is a real 800-53 control."""
        return control_id in self._controls

    def title(self, control_id: str) -> str:
        return self._controls[control_id].title

    def text(self, control_id: str) -> str:
        c = self._controls[control_id]
        return f"{c.title}. {c.text}"

    def family(self, control_id: str) -> str:
        return self._controls[control_id].family

    def resolve(self, reference: str) -> str | None:
        """Normalise a human control reference to a catalog ID, or None.

        Handles NIST's parenthesised enhancements (``IA-2(1)`` -> ``ia-2.1``)
        and statement-level citations (``IA-5c`` -> ``ia-5``, because the
        statement item belongs to the control and is not addressable itself).
        """
        if not reference:
            return None

        direct = reference.strip().lower()
        if direct in self._controls:
            return direct

        match = _REF_RE.match(reference)
        if not match:
            return None
        family, number, enhancement, _statement = match.groups()

        candidate = f"{family.lower()}-{number}"
        if enhancement:
            enhanced = f"{candidate}.{enhancement}"
            if enhanced in self._controls:
                return enhanced
            # An enhancement that does not exist is not silently downgraded to
            # its base control - that would assert coverage we cannot support.
            return None
        return candidate if candidate in self._controls else None

    def search(
        self,
        query: str,
        limit: int = 12,
        families: set[str] | None = None,
    ) -> list[str]:
        """Return candidate control IDs for an agent to reason over.

        Two signals are blended. Lexical overlap finds controls that share
        vocabulary with the query. Family targeting then guarantees that the
        families a practitioner would expect are represented at all - without
        it, a policy about phishing-resistant MFA never surfaces ia-2(1),
        because the two texts share almost no words, and an agent cannot
        propose a control it was never shown.

        This retrieves; it does not decide. The judgement stays with the agent.
        """
        terms = _tokenise(query)
        lexical: list[str] = []
        if terms:
            scored: list[tuple[float, str]] = []
            for cid, tokens in self._tokens.items():
                overlap = terms & tokens
                if not overlap:
                    continue
                # Normalise by query length so long controls do not dominate.
                scored.append((len(overlap) / len(terms), cid))
            scored.sort(key=lambda pair: (-pair[0], pair[1]))
            lexical = [cid for _score, cid in scored]

        if not families:
            return lexical[:limit]

        # Reserve roughly half the slots for family-targeted candidates.
        # Within a family, base controls (ia-2, ia-5) come before enhancements
        # (ia-2.1): mappings most often land on the base control, and a family
        # slot spent on an obscure enhancement is a slot wasted.
        per_family = max(3, (limit // 2) // max(len(families), 1))
        rank = {cid: i for i, cid in enumerate(lexical)}

        targeted: list[str] = []
        for family in sorted(families):
            members = [c.id for c in self._controls.values() if c.family == family]
            members.sort(
                key=lambda cid: (
                    "." in cid,                      # base controls first
                    rank.get(cid, 10**6),            # then by lexical relevance
                    cid,
                )
            )
            targeted.extend(members[:per_family])

        out: list[str] = []
        for cid in targeted + lexical:
            if cid not in out:
                out.append(cid)
            if len(out) >= limit:
                break
        return out

    def controls(self) -> Iterator[NistControl]:
        yield from self._controls.values()


def _walk(controls: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Yield controls and any nested enhancements."""
    for control in controls:
        yield control
        yield from _walk(control.get("controls", []))


def _prose(control: dict[str, Any]) -> str:
    """Flatten a control's statement parts into plain text for grounding."""
    chunks: list[str] = []

    def visit(parts: list[dict[str, Any]]) -> None:
        for part in parts:
            if prose := part.get("prose"):
                chunks.append(prose)
            visit(part.get("parts", []))

    visit(control.get("parts", []))
    return " ".join(chunks)


def _tokenise(text: str) -> set[str]:
    return {
        w for w in _WORD_RE.findall(text.lower()) if len(w) > 2 and w not in _STOPWORDS
    }


@lru_cache(maxsize=4)
def load_catalog(path: str) -> NistCatalog:
    """Cached loader - the catalog is ~5 MB and parsing it is not free."""
    return NistCatalog.load(path)
