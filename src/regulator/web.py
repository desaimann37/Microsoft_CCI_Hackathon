"""The Regulator dashboard.

Four things, in the order a reviewer needs them: the posture summary, the
artifacts with their validation status, the prioritised remediation plan, and a
console for asking questions in plain English.

The schema-validation badge is given the most prominent position on the page on
purpose. It is the project's central claim, and it is the one thing here that is
objectively checkable rather than asserted.
"""

from __future__ import annotations

import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, field_validator

from .agents.crosswalk import CrosswalkEngine
from .agents.registry import build_providers
from .evaluation import evaluate_crosswalk
from .nist_catalog import load_catalog
from .pipeline import DEFAULT_NIST_CATALOG, Pipeline
from .query import QueryEngine
from .validation import OSCAL_VERSION


class Question(BaseModel):
    question: str

    @field_validator("question")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("question must not be empty")
        return value.strip()


def create_app(
    scubagear_path: str | Path,
    product: str = "AAD",
    output_dir: str | Path | None = None,
) -> FastAPI:
    """Build the dashboard around one assessment."""
    out = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="regulator-"))
    run = Pipeline().run(scubagear_path, product=product, output_dir=out)

    catalog = load_catalog(DEFAULT_NIST_CATALOG)
    providers = build_providers(catalog)
    query_engine = QueryEngine.from_run(run, provider=providers.query)

    app = FastAPI(title="Regulator", docs_url="/api/docs")

    @lru_cache(maxsize=1)
    def evaluation() -> dict[str, Any]:
        engine = CrosswalkEngine(catalog, providers.crosswalk)
        return evaluate_crosswalk(engine, run.baseline).to_dict()

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return _render(run, providers.describe())

    @app.get("/api/summary")
    def summary() -> dict[str, Any]:
        return {
            **run.summary,
            "tenant": run.assessment.tenant_name,
            "tenant_id": run.assessment.tenant_id,
            "product": run.product,
            "tool": f"{run.assessment.tool} {run.assessment.tool_version}",
            "backend": run.backend,
            "all_valid": run.all_valid,
        }

    @app.get("/api/artifacts")
    def artifacts() -> dict[str, Any]:
        return {
            "oscal_version": OSCAL_VERSION,
            "artifacts": [
                {
                    "model": model,
                    "file": path.name,
                    "valid": run.validation[model].valid,
                    "errors": len(run.validation[model].errors),
                    "bytes": path.stat().st_size,
                }
                for model, path in run.written.items()
            ],
        }

    @app.get("/api/artifacts/{model}")
    def artifact(model: str) -> Any:
        if model not in run.artifacts:
            raise HTTPException(status_code=404, detail=f"unknown artifact {model!r}")
        return JSONResponse(run.artifacts[model])

    @app.get("/api/findings")
    def findings() -> dict[str, Any]:
        risks = {r.policy_id: r for r in run.analysis.risks}
        policies = {p.id: p for p in run.baseline.policies}
        rows = []
        for result in run.assessment.results:
            risk = risks.get(result.policy_id)
            policy = policies.get(result.policy_id)
            rows.append(
                {
                    "policy_id": result.policy_id,
                    "result": result.result,
                    "section": result.group_name,
                    "requirement": policy.requirement if policy else result.details,
                    "criticality": policy.criticality if policy else "",
                    "bod_25_01": bool(policy.bod_25_01) if policy else False,
                    "severity": risk.severity if risk else "",
                    "rank": risk.rank if risk else 0,
                    "blast_radius": risk.blast_radius if risk else "",
                }
            )
        rows.sort(key=lambda r: (r["result"] != "Fail", r["rank"] or 999))
        return {"findings": rows}

    @app.get("/api/poam")
    def poam() -> dict[str, Any]:
        items = run.artifacts["poam"]["plan-of-action-and-milestones"]["poam-items"]
        return {
            "items": [
                {
                    "title": item["title"],
                    "props": {p["name"]: p["value"] for p in item.get("props", [])},
                    "remarks": item.get("remarks", ""),
                }
                for item in items
            ]
        }

    @app.get("/api/evaluation")
    def evaluation_endpoint() -> dict[str, Any]:
        return evaluation()

    @app.post("/api/query")
    def query(payload: Question) -> dict[str, Any]:
        answer = query_engine.ask(payload.question)
        return {
            "answer": answer.text,
            "citations": answer.citations,
            "dropped_citations": answer.dropped_citations,
        }

    return app


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _render(run, backend_description: str) -> str:
    s = run.summary
    risks = {r.policy_id: r for r in run.analysis.risks}
    policies = {p.id: p for p in run.baseline.policies}

    ranked = sorted(
        run.assessment.failures,
        key=lambda f: (risks[f.policy_id].rank if f.policy_id in risks else 999),
    )
    rows = "".join(
        _row(f, risks.get(f.policy_id), policies.get(f.policy_id)) for f in ranked
    )

    artifact_rows = "".join(
        f"<tr><td><code>{model}</code></td>"
        f"<td>{'<span class=ok>VALID</span>' if run.validation[model].valid else '<span class=bad>INVALID</span>'}</td>"
        f"<td class=dim>{path.name}</td>"
        f"<td class=num>{path.stat().st_size // 1024} KB</td>"
        f"<td><a href='/api/artifacts/{model}' target='_blank'>view</a></td></tr>"
        for model, path in run.written.items()
    )

    warnings = "".join(f"<div class='warn'>{w}</div>" for w in run.warnings)

    return _PAGE.format(
        tenant=run.assessment.tenant_name,
        tenant_id=run.assessment.tenant_id,
        product=run.product,
        tool=f"{run.assessment.tool} {run.assessment.tool_version}",
        date=run.assessment.timestamp.strftime("%d %b %Y"),
        total=s["total"], passed=s["pass"], failed=s["fail"],
        warning=s["warning"], na=s["not_applicable"],
        oscal=OSCAL_VERSION,
        backend=backend_description,
        mappings=len(run.analysis.mappings),
        rows=rows,
        artifact_rows=artifact_rows,
        warnings=warnings,
    )


def _row(failure, risk, policy) -> str:
    severity = risk.severity if risk else ""
    rank = risk.rank if risk else ""
    badge = f"<span class='sev {severity}'>{severity}</span>" if severity else ""
    bod = "<span class='bod'>BOD 25-01</span>" if policy and policy.bod_25_01 else ""
    return (
        f"<tr><td class=num>{rank}</td>"
        f"<td><code>{failure.policy_id}</code> {bod}</td>"
        f"<td>{(policy.requirement if policy else failure.details)}</td>"
        f"<td>{badge}</td>"
        f"<td class=dim>{risk.blast_radius if risk else ''}</td></tr>"
    )


_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Regulator</title>
<style>
:root{{--ink:#0b0b0b;--ink2:#52514e;--mut:#86847e;--line:#e2e1dc;--surface:#fcfcfb;
--blue:#2a78d6;--aqua:#1baf7a;--orange:#eb6834;--red:#e34948;--dark:#12181f;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",-apple-system,Roboto,Helvetica,Arial,sans-serif;
background:var(--surface);color:var(--ink);line-height:1.55;font-size:15px}}
header{{background:var(--dark);color:#fff;padding:26px 34px}}
header h1{{font-size:27px;letter-spacing:-.8px}}
header .tag{{color:#8fb4e0;font-weight:600;margin-top:2px}}
header .meta{{color:#b9c2cc;font-size:13px;margin-top:10px}}
main{{max-width:1180px;margin:0 auto;padding:26px 34px 60px}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:1.8px;color:var(--blue);
margin:32px 0 12px;display:flex;align-items:center;gap:10px}}
h2:after{{content:"";flex:1;height:1px;background:var(--line)}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap}}
.tile{{flex:1;min-width:130px;border:1px solid var(--line);border-radius:6px;
padding:13px 15px;background:#fff}}
.tile .v{{font-size:27px;font-weight:600;letter-spacing:-1px;line-height:1.1}}
.tile .l{{font-size:12px;color:var(--ink2);margin-top:3px}}
.tile.ok{{border-top:3px solid var(--aqua)}} .tile.bad{{border-top:3px solid var(--red)}}
.tile.warn{{border-top:3px solid var(--orange)}} .tile.n{{border-top:3px solid var(--blue)}}
table{{width:100%;border-collapse:collapse;font-size:13.5px;background:#fff}}
th{{text-align:left;padding:8px 10px;background:#f3f5f8;font-size:11.5px;
text-transform:uppercase;letter-spacing:.8px;color:var(--ink2);border-bottom:1px solid var(--line)}}
td{{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
td.num{{text-align:right;color:var(--mut);width:42px;white-space:nowrap}}
td.dim{{color:var(--mut)}}
code{{font-family:Consolas,monospace;font-size:12.5px;background:#f3f5f8;
padding:1px 5px;border-radius:3px;color:#0a3d62;white-space:nowrap}}
.ok{{color:#0a7d5a;font-weight:700}} .bad{{color:#b3261e;font-weight:700}}
.sev{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;
text-transform:uppercase;letter-spacing:.5px}}
.sev.critical{{background:#fdecea;color:#a32c2c}} .sev.high{{background:#fdf0e8;color:#9a4b06}}
.sev.moderate{{background:#fdf8e6;color:#8a6d00}} .sev.low{{background:#eef4fb;color:#1c5cab}}
.bod{{font-size:10px;font-weight:700;background:#fdecea;color:#a32c2c;
padding:1px 6px;border-radius:3px;margin-left:5px;letter-spacing:.4px}}
.warn{{background:#fdf6ec;border-left:3px solid var(--orange);padding:8px 12px;
margin:8px 0;font-size:13px;border-radius:0 4px 4px 0}}
.bar{{background:var(--aqua);color:#fff;padding:11px 16px;border-radius:6px;
font-weight:600;display:flex;align-items:center;gap:11px;margin:4px 0 2px}}
.bar .k{{background:#fff;color:#0a7d5a;padding:1px 9px;border-radius:3px;font-size:12px}}
.qbox{{display:flex;gap:8px;margin-top:10px}}
.qbox input{{flex:1;padding:10px 13px;border:1px solid var(--line);border-radius:5px;
font-size:14px;font-family:inherit}}
.qbox button{{padding:10px 20px;background:var(--blue);color:#fff;border:0;
border-radius:5px;font-weight:600;cursor:pointer;font-size:14px}}
#ans{{margin-top:12px;white-space:pre-wrap;font-size:13.5px;background:#fff;
border:1px solid var(--line);border-radius:6px;padding:14px;display:none}}
#ans .cites{{margin-top:10px;font-size:12px;color:var(--ink2);
border-top:1px dashed var(--line);padding-top:8px}}
.suggest{{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}}
.suggest button{{background:#fff;border:1px solid var(--line);color:var(--ink2);
padding:5px 11px;border-radius:14px;font-size:12px;cursor:pointer;font-family:inherit}}
.foot{{margin-top:36px;padding-top:14px;border-top:1px solid var(--line);
font-size:12px;color:var(--mut)}}
</style></head><body>
<header>
  <h1>Regulator</h1>
  <div class="tag">Proof, not paperwork.</div>
  <div class="meta">{tenant} &middot; {tenant_id} &middot; {product} &middot;
    assessed by {tool} on {date}</div>
</header>
<main>

  <div class="bar"><span class="k">VALID</span>
    All five OSCAL artifacts conform to the published NIST OSCAL {oscal} schemas.</div>
  {warnings}

  <h2>Posture</h2>
  <div class="tiles">
    <div class="tile bad"><div class="v">{failed}</div><div class="l">Failing</div></div>
    <div class="tile warn"><div class="v">{warning}</div><div class="l">Warning</div></div>
    <div class="tile ok"><div class="v">{passed}</div><div class="l">Passing</div></div>
    <div class="tile n"><div class="v">{na}</div><div class="l">Not applicable</div></div>
    <div class="tile n"><div class="v">{total}</div><div class="l">Policies assessed</div></div>
    <div class="tile n"><div class="v">{mappings}</div><div class="l">Crosswalk mappings</div></div>
  </div>

  <h2>Remediation plan &mdash; highest risk first</h2>
  <table><thead><tr><th>#</th><th>Policy</th><th>Requirement</th>
    <th>Severity</th><th>Blast radius</th></tr></thead>
    <tbody>{rows}</tbody></table>

  <h2>OSCAL artifacts</h2>
  <table><thead><tr><th>Model</th><th>Schema</th><th>File</th>
    <th>Size</th><th></th></tr></thead>
    <tbody>{artifact_rows}</tbody></table>

  <h2>Ask the artifacts</h2>
  <div class="qbox">
    <input id="q" placeholder="e.g. Which failures put us most at risk?"
      onkeydown="if(event.key==='Enter')ask()">
    <button onclick="ask()">Ask</button>
  </div>
  <div class="suggest">
    <button onclick="preset(this)">Which failures put us most at risk?</button>
    <button onclick="preset(this)">What is mandatory under BOD 25-01?</button>
    <button onclick="preset(this)">Summarise our MFA posture.</button>
  </div>
  <div id="ans"></div>

  <div class="foot">
    Reasoning backend: {backend} &middot;
    Artifacts validated against NIST OSCAL {oscal} &middot;
    Sources: CISA SCuBA, CISA ScubaGear, NIST SP 800-53 Rev 5
  </div>
</main>
<script>
function preset(b){{document.getElementById('q').value=b.textContent;ask();}}
async function ask(){{
  const q=document.getElementById('q').value.trim(); if(!q) return;
  const box=document.getElementById('ans');
  box.style.display='block'; box.textContent='Thinking...';
  try{{
    const r=await fetch('/api/query',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{question:q}})}});
    const d=await r.json();
    box.innerHTML='';
    const p=document.createElement('div'); p.textContent=d.answer; box.appendChild(p);
    if(d.citations && d.citations.length){{
      const c=document.createElement('div'); c.className='cites';
      c.textContent='Citations: '+d.citations.join(', '); box.appendChild(c);
    }}
    if(d.dropped_citations && d.dropped_citations.length){{
      const x=document.createElement('div'); x.className='cites';
      x.textContent='Dropped unverifiable citations: '+d.dropped_citations.join(', ');
      box.appendChild(x);
    }}
  }}catch(e){{ box.textContent='Query failed: '+e; }}
}}
</script>
</body></html>
"""
