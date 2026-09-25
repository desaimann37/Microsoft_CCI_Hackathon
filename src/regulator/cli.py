"""Regulator's command line interface.

Deliberately thin: it orchestrates, formats, and sets exit codes. The exit codes
carry real weight - ``regulator validate`` returning non-zero is what stops an
invalid artifact reaching an auditor from a CI pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .agents.crosswalk import CrosswalkEngine
from .agents.registry import build_providers
from .evaluation import evaluate_crosswalk
from .nist_catalog import load_catalog
from .parsers.scuba_baseline import parse_baseline
from .pipeline import DEFAULT_BASELINE_DIR, DEFAULT_NIST_CATALOG, Pipeline
from .query import QueryEngine
from .validation import OSCAL_MODELS, OSCAL_VERSION, validate

app = typer.Typer(
    add_completion=False,
    help="Turn CISA SCuBA baselines and ScubaGear results into validated NIST OSCAL.",
)
console = Console()

RESULT_STYLE = {
    "Pass": "green",
    "Fail": "red",
    "Warning": "yellow",
    "N/A": "dim",
}


@app.command()
def build(
    scubagear: Path = typer.Argument(..., help="ScubaGear ScubaResults JSON file."),
    product: str = typer.Option("AAD", "--product", "-p", help="AAD, EXO, Teams, ..."),
    out: Path = typer.Option(Path("artifacts"), "--out", "-o", help="Output directory."),
) -> None:
    """Build all five OSCAL artifacts from a ScubaGear report."""
    run = Pipeline().run(scubagear, product=product, output_dir=out)

    console.print(
        Panel.fit(
            f"[bold]{run.assessment.tenant_name}[/bold]  "
            f"[dim]({run.assessment.tenant_id})[/dim]\n"
            f"{run.assessment.tool} {run.assessment.tool_version} · "
            f"{run.product} · {run.assessment.timestamp:%Y-%m-%d}",
            title="Tenant assessed",
            border_style="blue",
        )
    )

    summary = Table(show_header=True, header_style="bold")
    summary.add_column("Result")
    summary.add_column("Count", justify="right")
    for label, key in (
        ("Pass", "pass"), ("Fail", "fail"),
        ("Warning", "warning"), ("N/A", "not_applicable"),
    ):
        summary.add_row(
            f"[{RESULT_STYLE[label]}]{label}[/]", str(run.summary[key])
        )
    summary.add_row("[bold]Total[/]", f"[bold]{run.summary['total']}[/]")
    console.print(summary)

    artifacts = Table(show_header=True, header_style="bold")
    artifacts.add_column("OSCAL artifact")
    artifacts.add_column("Schema")
    artifacts.add_column("File")
    for model, path in run.written.items():
        ok = run.validation[model].valid
        artifacts.add_row(
            model,
            "[green]VALID[/]" if ok else "[red]INVALID[/]",
            str(path.name),
        )
    console.print(artifacts)

    console.print(
        f"[dim]Validated against NIST OSCAL {OSCAL_VERSION} schemas · "
        f"AI backend: {run.backend} · "
        f"{len(run.analysis.mappings)} crosswalk mappings, "
        f"{len(run.analysis.risks)} risk judgements[/dim]"
    )
    for warning in run.warnings:
        console.print(f"[yellow]warning:[/] {warning}")

    if not run.all_valid:
        raise typer.Exit(code=1)


@app.command()
def validate_artifact(
    path: Path = typer.Argument(..., help="An OSCAL JSON file."),
    model: str = typer.Option(..., "--model", "-m", help=f"One of: {', '.join(OSCAL_MODELS)}"),
) -> None:
    """Validate an OSCAL artifact against its published NIST schema."""
    if not Path(path).exists():
        console.print(f"[red]error:[/] no such file: {path}")
        raise typer.Exit(code=2)
    if model not in OSCAL_MODELS:
        console.print(
            f"[red]error:[/] unknown model {model!r}; "
            f"expected one of: {', '.join(OSCAL_MODELS)}"
        )
        raise typer.Exit(code=2)
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]INVALID[/] {Path(path).name} is not valid JSON: {exc}")
        raise typer.Exit(code=1) from None
    result = validate(document, model)
    if result.valid:
        console.print(
            f"[green]VALID[/] {path.name} conforms to the OSCAL "
            f"{OSCAL_VERSION} {model} schema"
        )
        return
    console.print(f"[red]INVALID[/] {path.name}: {len(result.errors)} error(s)")
    for error in result.errors[:15]:
        console.print(f"  [red]·[/] {error}")
    raise typer.Exit(code=1)


# Registered under the friendlier name as well.
app.command("validate")(validate_artifact)


@app.command()
def evaluate(
    product: str = typer.Option("AAD", "--product", "-p"),
    baseline_dir: Path = typer.Option(DEFAULT_BASELINE_DIR, "--baselines"),
    json_out: Path | None = typer.Option(None, "--json", help="Write the report as JSON."),
) -> None:
    """Score the crosswalk against CISA's own published NIST mapping."""
    catalog = load_catalog(DEFAULT_NIST_CATALOG)
    baseline = parse_baseline(baseline_dir / f"{product.lower()}.md")
    providers = build_providers(catalog)
    engine = CrosswalkEngine(catalog, providers.crosswalk)

    report = evaluate_crosswalk(engine, baseline)

    table = Table(
        title=f"Crosswalk accuracy vs CISA ground truth · {report.provider}",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Match")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("Hit rate", justify="right")
    table.add_row(
        "exact",
        f"{report.exact.precision:.2f}",
        f"{report.exact.recall:.2f}",
        f"{report.exact.f1:.2f}",
        f"{report.exact_hit_rate:.0%}",
    )
    table.add_row(
        "family",
        f"{report.family.precision:.2f}",
        f"{report.family.recall:.2f}",
        f"{report.family.f1:.2f}",
        f"{report.family_hit_rate:.0%}",
    )
    console.print(table)
    console.print(
        f"[dim]{report.policies_evaluated} policies with CISA mappings · "
        f"backend: {providers.backend}[/dim]"
    )

    if json_out:
        Path(json_out).write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        console.print(f"[dim]report written to {json_out}[/dim]")


@app.command()
def query(
    question: str = typer.Argument(..., help="A plain-English question."),
    source: Path = typer.Option(..., "--source", "-s", help="ScubaGear JSON file."),
    product: str = typer.Option("AAD", "--product", "-p"),
    out: Path = typer.Option(Path("artifacts"), "--out", "-o"),
) -> None:
    """Ask a question about a tenant's posture, answered with citations."""
    run = Pipeline().run(source, product=product, output_dir=out)
    providers = build_providers(load_catalog(DEFAULT_NIST_CATALOG))
    engine = QueryEngine.from_run(run, provider=providers.query)

    answer = engine.ask(question)
    console.print(Panel(answer.text, title=question, border_style="blue"))
    if answer.citations:
        console.print("[bold]Citations:[/] " + ", ".join(answer.citations))
    if answer.dropped_citations:
        console.print(
            "[yellow]Dropped unverifiable citations:[/] "
            + ", ".join(answer.dropped_citations)
        )


@app.command()
def serve(
    source: Path = typer.Option(..., "--source", "-s", help="ScubaGear JSON file."),
    product: str = typer.Option("AAD", "--product", "-p"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Serve the posture dashboard."""
    import uvicorn

    from .web import create_app

    console.print(f"[green]Regulator[/] dashboard on http://{host}:{port}")
    uvicorn.run(create_app(source, product), host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    app()
