"""Deterministic identifier generation.

Every UUID in a Regulator artifact is derived from stable source keys rather than
generated randomly, so that re-running the pipeline over unchanged input produces
byte-identical output and cross-document references keep resolving.
"""

from __future__ import annotations

import uuid

# Fixed namespace for this project. Never change it: doing so re-identifies every
# object in every artifact ever emitted.
NAMESPACE = uuid.UUID("6f3d9c2a-1b4e-5a7f-9c8d-2e5b7a1f4c30")

# Joining parts with a character that cannot occur in a source key keeps
# ("ab", "c") distinct from ("a", "bc").
_SEP = "\x1f"


def deterministic_uuid(*parts: str) -> str:
    """Return a stable RFC 4122 UUID derived from ``parts``.

    The first part is conventionally the object kind ("control", "finding",
    "risk", ...) so that objects of different kinds describing the same policy
    do not collide.
    """
    if not parts:
        raise ValueError("deterministic_uuid requires at least one part")
    return str(uuid.uuid5(NAMESPACE, _SEP.join(parts)))
