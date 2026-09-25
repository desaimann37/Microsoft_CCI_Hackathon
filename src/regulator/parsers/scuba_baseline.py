"""Parse a CISA SCuBA Secure Configuration Baseline markdown document.

The baseline is written for humans, so this parser leans on the few machine-
readable affordances CISA embedded in it:

  * ``#### MS.AAD.1.1v1``            - a policy heading, bare ID and nothing else
  * ``<!--Policy: ...; Criticality: SHALL -->``  - structured metadata
  * ``- _Rationale:_ ...``           - labelled prose fields
  * ``- _NIST SP 800-53 ...:_ CM-7`` - CISA's own control mapping

Headings under the *Implementation* section look like ``#### MS.AAD.2.1v1
Instructions`` (one of them with a double space after the hashes), so policy
headings are matched only when the ID is the entire heading text.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import BaselineGroup, ScubaBaseline, ScubaPolicy

# "## 3. Strong Authentication and a Secure Registration Process"
_GROUP_RE = re.compile(r"^##\s+(\d+)\.\s+(.+?)\s*$")
# "### Policies", "### Implementation", ...
_SUBSECTION_RE = re.compile(r"^###\s+(.+?)\s*$")
# "#### MS.AAD.1.1v1" and nothing after it
_POLICY_RE = re.compile(r"^####\s+(MS\.[A-Z0-9]+\.\d+\.\d+v\d+)\s*$")
# "<!--Policy: MS.AAD.1.1v1; Criticality: SHALL -->"
_CRITICALITY_RE = re.compile(r"<!--\s*Policy:.*?Criticality:\s*([A-Za-z]+)", re.I)
_RATIONALE_RE = re.compile(r"^-\s+_Rationale:_\s*(.+?)\s*$")
_LAST_MODIFIED_RE = re.compile(r"^-\s+_Last modified:_\s*(.+?)\s*$")
_NIST_RE = re.compile(r"^-\s+_NIST SP 800-53[^:]*:_\s*(.+?)\s*$")
# "[T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)"
_MITRE_RE = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\s*:")
_TITLE_RE = re.compile(r"^#\s+(.+?)\s*$")

_NO_MAPPING = {"", "n/a", "na", "none", "not applicable"}


def parse_baseline(path: str | Path) -> ScubaBaseline:
    """Parse a SCuBA baseline markdown file into the internal model."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()

    title = ""
    groups: list[BaselineGroup] = []
    policies: list[ScubaPolicy] = []

    group_number = group_name = ""
    subsection = ""
    block: list[str] | None = None
    block_id = ""

    def flush() -> None:
        nonlocal block, block_id
        if block is not None and block_id:
            policies.append(
                _policy_from_block(block_id, block, group_number, group_name)
            )
        block, block_id = None, ""

    for line in lines:
        if not title and (m := _TITLE_RE.match(line)):
            title = m.group(1)

        if m := _GROUP_RE.match(line):
            flush()
            group_number, group_name = m.group(1), m.group(2)
            groups.append(BaselineGroup(number=group_number, name=group_name))
            subsection = ""
            continue

        if m := _SUBSECTION_RE.match(line):
            flush()
            subsection = m.group(1)
            continue

        if m := _POLICY_RE.match(line):
            flush()
            # Only headings inside the "Policies" subsection define policies;
            # the Implementation section repeats the IDs as instructions.
            if subsection.lower().startswith("policies"):
                block, block_id = [], m.group(1)
            continue

        if line.startswith("####"):
            # Any other level-4 heading ends the current policy block.
            flush()
            continue

        if block is not None:
            block.append(line)

    flush()

    product = policies[0].id.split(".")[1] if policies else ""
    return ScubaBaseline(
        product=product,
        title=title,
        groups=tuple(groups),
        policies=tuple(policies),
    )


def _policy_from_block(
    policy_id: str, block: list[str], group_number: str, group_name: str
) -> ScubaPolicy:
    requirement = _first_paragraph(block)

    criticality = "SHALL"
    rationale = last_modified = None
    nist: list[str] = []
    mitre: list[str] = []
    bod = False

    for line in block:
        if m := _CRITICALITY_RE.search(line):
            criticality = m.group(1).upper()
        if m := _RATIONALE_RE.match(line):
            rationale = m.group(1)
        if m := _LAST_MODIFIED_RE.match(line):
            last_modified = m.group(1)
        if m := _NIST_RE.match(line):
            nist = _split_controls(m.group(1))
        for t in _MITRE_RE.findall(line):
            if t not in mitre:
                mitre.append(t)
        if "BOD 25-01 Requirement" in line:
            bod = True

    return ScubaPolicy(
        id=policy_id,
        requirement=requirement,
        criticality=criticality,
        group_number=group_number,
        group_name=group_name,
        rationale=rationale,
        last_modified=last_modified,
        bod_25_01=bod,
        nist_controls=tuple(nist),
        mitre_techniques=tuple(mitre),
    )


def _first_paragraph(block: list[str]) -> str:
    """The requirement is the first prose paragraph after the policy heading.

    Later paragraphs are guidance, and the shields.io badge block that follows
    must not leak into the control statement.
    """
    collected: list[str] = []
    for line in block:
        stripped = line.strip()
        if not stripped:
            if collected:
                break
            continue
        if stripped.startswith(("[![", "<!--", "- _", "|")):
            break
        collected.append(stripped)
    return " ".join(collected)


def _split_controls(value: str) -> list[str]:
    """Split CISA's comma-separated control list, dropping 'N/A' style values."""
    if value.strip().lower() in _NO_MAPPING:
        return []
    out: list[str] = []
    for part in value.split(","):
        # Strip markdown emphasis and stray backticks CISA occasionally uses.
        control = part.strip().strip("*_`").strip()
        if control and control.lower() not in _NO_MAPPING and control not in out:
            out.append(control)
    return out
