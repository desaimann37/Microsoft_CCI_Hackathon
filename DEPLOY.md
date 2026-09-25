# Deploying Regulator

A hosted instance needs **no credentials at all**. It serves the public CISA
sample report committed to this repository, so a reviewer opens the URL and
clicks — no account, no API key, nothing to configure.

That is deliberate. An API key on a public host is something to leak and
something for a stranger to spend. With none present the agents fall back to the
offline baseline, and the dashboard says so in its footer.

---

## Azure App Service (Linux, Python)

### 1. Create the Web App

Azure Portal → **Create a resource** → **Web App**.

| Field | Value |
|---|---|
| Publish | **Code** |
| Runtime stack | **Python 3.12** (or later) |
| Operating System | **Linux** |
| Region | one your subscription's policy permits |
| Pricing plan | **B1 Basic** for a custom domain — see note below |

> **Free F1 does not support custom domains or HTTPS certificates.** On F1 you
> get `https://<app-name>.azurewebsites.net` and nothing else, which is perfectly
> adequate for judging. You only need **B1** (around $13/month, well inside a
> $100 student credit) if you want your own domain on it.

### 2. Deploy from GitHub

In the new Web App → **Deployment Center**:

- Source: **GitHub**, authorise if prompted
- Organization / Repository / Branch: this repo, `main`
- Build provider: **GitHub Actions** (the default)
- **Save**

Azure adds a workflow to the repository and builds. The first build takes a few
minutes, mostly installing dependencies.

### 3. Set the startup command

**Configuration** → **General settings** → **Startup Command**:

```
PYTHONPATH=/home/site/wwwroot/src python -m uvicorn regulator.asgi:app --host 0.0.0.0 --port 8000
```

`PYTHONPATH` is required: the package lives under `src/`, and App Service starts
the process from a directory that would not otherwise find it.

**Save**, then **Restart** the app.

### 4. Check it

Open `https://<app-name>.azurewebsites.net`. You should see the dashboard with
the green **VALID** bar.

If it does not come up, read the log stream: **Monitoring** → **Log stream**.

---

## Optional settings

Everything has a working default. Set these only if you want to change something.

| Variable | Default | Purpose |
|---|---|---|
| `REGULATOR_SOURCE` | the bundled CISA sample | serve a different ScubaGear report |
| `REGULATOR_PRODUCT` | `AAD` | serve a different M365 product |
| `REGULATOR_OUTPUT_DIR` | a temp directory | where generated artifacts are written |

**Do not set the Foundry variables on a public instance.** `AZURE_OPENAI_*` and
`MODEL_*` are for local runs and for the evaluation, where the cost and the key
stay with you.

---

## Your own domain via Cloudflare

Requires the **B1** plan or higher.

1. In the Web App → **Custom domains** → **Add custom domain**. Azure shows a
   **Custom Domain Verification ID**. Copy it.

2. In Cloudflare DNS, add two records for your chosen hostname
   (`regulator.yourdomain.com` in this example):

   | Type | Name | Content | Proxy |
   |---|---|---|---|
   | CNAME | `regulator` | `<app-name>.azurewebsites.net` | **DNS only** (grey cloud) |
   | TXT | `asuid.regulator` | the verification ID from step 1 | — |

   The proxy must be **off** while Azure validates. You can turn it on
   afterwards.

3. Back in Azure, **Validate**, then **Add**.

4. **Custom domains** → **Add binding** → create a free **App Service Managed
   Certificate** for the hostname, and set TLS to **SNI SSL**.

DNS changes usually take a few minutes; Cloudflare is quick.

---

## Running it as a container instead

The app is an ordinary ASGI application, so any container host works:

```bash
pip install -r requirements.txt
PYTHONPATH=src python -m uvicorn regulator.asgi:app --host 0.0.0.0 --port 8000
```

---

## What a reviewer can do on the hosted instance

- See the posture summary for the sample tenant — 30 policies, 11 failing
- Read the remediation plan, ranked by risk
- Confirm all five OSCAL artifacts report **VALID**
- Open the raw OSCAL at `/api/artifacts/catalog`, `/poam`, and so on
- Ask a question in plain English and see the citations
- Browse the API at `/api/docs`

The hosted instance is read-only. Building artifacts, validating them, running
the evaluation and the tamper test are all done from the CLI — see the README.
