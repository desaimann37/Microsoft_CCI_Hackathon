"""ASGI entrypoint for hosted deployments.

Start with::

    uvicorn regulator.asgi:app --host 0.0.0.0 --port $PORT

A hosting platform imports a module-level ``app`` and binds the socket itself,
so the Typer ``serve`` command is not usable there. Everything is configured
from environment variables, which means the same code runs unchanged locally and
in the cloud.

**A hosted instance is deliberately credential-free.** It serves the public CISA
sample report committed to this repository, so a reviewer can open the URL and
click around without an account. No API key belongs on a public host: there is
nothing to leak, and no one can spend someone else's model quota through the
query box. With no credentials present the agents fall back to the offline
baseline, and the dashboard says so in its footer.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from . import paths
from .web import create_app

#: The public sample report, committed to the repository.
DEFAULT_SOURCE = str(paths.SAMPLE_REPORT)
DEFAULT_PRODUCT = "AAD"

#: Generated artifacts go to a writable temp directory. Many hosts mount the
#: application directory read-only.
OUTPUT_DIR = os.environ.get(
    "REGULATOR_OUTPUT_DIR",
    tempfile.mkdtemp(prefix="regulator-artifacts-"),
)
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)


def resolve_source() -> str:
    """The ScubaGear report to serve.

    An operator's explicit path is used verbatim. The bundled default is
    resolved from this file's location, not the working directory - a host may
    start the process from anywhere.
    """
    return os.environ.get("REGULATOR_SOURCE", "").strip() or DEFAULT_SOURCE


def resolve_product() -> str:
    """The Microsoft 365 product to serve results for."""
    return os.environ.get("REGULATOR_PRODUCT", "").strip() or DEFAULT_PRODUCT


#: The application object a host imports.
app = create_app(resolve_source(), resolve_product(), output_dir=OUTPUT_DIR)
