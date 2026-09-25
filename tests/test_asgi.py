"""The ASGI entrypoint used when Regulator is hosted.

A hosting platform starts the app by importing a module-level ``app`` object and
binding it itself; it cannot run a Typer command. This module provides that
object, configured entirely from environment variables so the same image works
locally and in the cloud.

A hosted instance is deliberately read-only and credential-free: it runs on the
public CISA sample report committed to this repository, so a reviewer can open it
and click without an account, and there is no API key on a public server to
leak or to bill.
"""

import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def asgi_module():
    from regulator import asgi

    return asgi


def test_exposes_a_module_level_app(asgi_module):
    """What `uvicorn regulator.asgi:app` imports."""
    assert isinstance(asgi_module.app, FastAPI)


def test_defaults_to_the_committed_sample_report(asgi_module):
    """No configuration required for the public demo to work."""
    assert "ScubaResults-sample.json" in asgi_module.DEFAULT_SOURCE


def test_source_is_configurable(monkeypatch):
    monkeypatch.setenv("REGULATOR_SOURCE", "some/other/report.json")
    from regulator.asgi import resolve_source

    assert resolve_source() == "some/other/report.json"


def test_product_is_configurable(monkeypatch):
    monkeypatch.setenv("REGULATOR_PRODUCT", "EXO")
    from regulator.asgi import resolve_product

    assert resolve_product() == "EXO"


def test_product_defaults_to_entra_id(monkeypatch):
    monkeypatch.delenv("REGULATOR_PRODUCT", raising=False)
    from regulator.asgi import resolve_product

    assert resolve_product() == "AAD"


def test_the_hosted_app_serves_the_dashboard(asgi_module):
    client = TestClient(asgi_module.app)
    response = client.get("/")
    assert response.status_code == 200
    assert "Regulator" in response.text


def test_the_hosted_app_serves_the_api(asgi_module):
    client = TestClient(asgi_module.app)
    data = client.get("/api/summary").json()
    assert data["total"] == 30
    assert data["all_valid"] is True


def test_hosted_instance_runs_without_credentials(asgi_module, monkeypatch):
    """The public demo must never depend on an API key being present."""
    for var in ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY",
                "AZURE_OPENAI_DEPLOYMENT", "MODEL_ENDPOINT", "MODEL_API_KEY",
                "MODEL_NAME"):
        monkeypatch.delenv(var, raising=False)
    client = TestClient(asgi_module.app)
    assert client.get("/api/summary").json()["all_valid"] is True


def test_writes_artifacts_to_a_writable_location(asgi_module):
    """Many hosts give you a read-only app directory and a temp dir."""
    assert os.path.isdir(asgi_module.OUTPUT_DIR)


def test_default_source_does_not_depend_on_the_working_directory(tmp_path, monkeypatch):
    """A host may start the process from anywhere. Resolving the bundled sample
    relative to the current directory is the classic way a deployment dies."""
    monkeypatch.delenv("REGULATOR_SOURCE", raising=False)
    monkeypatch.chdir(tmp_path)
    from regulator.asgi import resolve_source

    assert Path(resolve_source()).is_file()


def test_explicit_source_is_left_alone(monkeypatch):
    """An operator pointing at their own report gets exactly that path."""
    monkeypatch.setenv("REGULATOR_SOURCE", "/mnt/reports/their-report.json")
    from regulator.asgi import resolve_source

    assert resolve_source() == "/mnt/reports/their-report.json"
