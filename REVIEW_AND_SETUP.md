# SecurePipeline review and local setup

Reviewed on 5 November 2026. The original ZIP remains unchanged; this extracted workspace contains the fixes.

## What the project does

SecurePipeline connects security scanning to a deployment decision and a dashboard. Semgrep checks code, Gitleaks finds credentials, Syft inventories software packages, and Trivy checks dependencies and container images. Python wrappers normalize scanner results. The aggregator deduplicates findings, the gate blocks HIGH/CRITICAL findings and incomplete coverage, and the report generator writes JSON and HTML.

GitHub Actions orchestrates the scanners and gate. Its deployment job currently prints a demonstration approval message; it does not deploy an application. Optional report delivery sends results to FastAPI. FastAPI persists scans, findings, scanner status, risk priority, and score history in SQLite. React/Vite displays those records through a local API proxy. The separate Code Analyzer uses pattern matching and provides rule-based suggestions; it does not execute submitted code or replace a full scanner.

Important entry points: `.github/workflows/security.yml`, `scanners/scanner_manager.py`, `scripts/aggregate.py`, `scripts/security_gate.py`, `scripts/report_generator.py`, `dashboard/backend/app/main.py`, and `dashboard/frontend/src/App.jsx`.

## Fixes made

1. Incomplete scans no longer receive a fallback score of 100. Their score is unavailable even if the input supplies a score.
2. Backend file ingestion resolves paths and permits only JSON files under `dashboard/backend/reports`, rejecting traversal and paths outside that directory.
3. Scan/finding pagination and dashboard history enforce positive limits up to 100; negative offsets and zero limits return HTTP 422.
4. CI report delivery uses a Bash array to preserve the complete API key header as one argument.
5. Windows startup derives paths from the script directory, records process IDs/logs, runs hidden, accepts custom ports, and refuses occupied ports rather than killing their processes.
6. Vite binds to loopback and accepts `VITE_PROXY_TARGET` for the backend proxy.
7. Gitleaks, Syft, and Trivy reject missing/invalid reports instead of returning a successful clean scan. File-based scanners remove their previous generated report before invocation. Trivy nonzero exits fail even when a report exists. Semgrep requires an accepted exit code, a result list, and no reported errors.
8. Scanner tests use temporary directories so they do not overwrite bundled reports. Six regression tests cover HTTP boundaries, malformed output, and stale output.

## Verified results

- Root suite: 25 tests passed.
- Backend suite: 43 tests passed.
- Frontend: `npm.cmd ci --no-audit --no-fund` succeeded; `npm.cmd run build` succeeded.
- Backend health returned OK; frontend returned HTTP 200; dashboard summary worked through the Vite proxy.
- Bundled report ingestion succeeded: scan ID 1, report `sec-rep-20261103160701`, 557 findings, BLOCK, score 0.
- Workflow YAML validation passed. GitHub Actions execution and authenticated delivery were not exercised remotely.
- The build warns about a JavaScript bundle above 500 kB. Dependency installation warns that the installed Recharts 2 branch is deprecated.

## Running locally

The services started for this review use:

- Dashboard: http://127.0.0.1:18766
- API documentation: http://127.0.0.1:18765/docs
- Health: http://127.0.0.1:18765/api/health

Ports 8000 and 8001 were occupied. The dashboard uses saved demonstration data, not results of a new security scan. Service logs and launch process IDs are under `logs/`.

From the extracted project root, after stopping these services, restart with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start_dashboard.ps1 -BackendPort 18765 -FrontendPort 18766
```

Add `-OpenBrowser` to open the dashboard. Default ports are 8000 and 5173. The launcher expects installed dependencies. For a fresh machine, install Python and Node, then:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt -r dashboard/backend/requirements.txt
Push-Location dashboard/frontend
npm.cmd ci
Pop-Location
```

This review used the machine's existing Python 3.13 environment, which already provided the required backend libraries, and installed frontend dependencies from the lockfile. It did not validate a fresh isolated Python installation. Activate the desired Python environment before using the launcher.

Run verification from the project root:

```powershell
python -m unittest discover -s tests -v
Push-Location dashboard/backend
python -m unittest discover -s tests -v
Pop-Location
Push-Location dashboard/frontend
npm.cmd run build
Pop-Location
```

## Remaining findings and validation limits

- Semgrep, Gitleaks, Syft, Trivy, and Docker were absent from PATH. Real scanner execution, container builds, vulnerability database access, and end-to-end CI need a suitably provisioned environment. Wrapper tests include missing-tool handling and mocked outputs, so passing tests do not establish that a real scan ran.
- API key enforcement applies to ingestion and is optional when `SECUREPIPELINE_API_KEY` is empty. Read APIs remain unauthenticated. The local services bind to loopback. Production identity/access controls require additional work.
- Ingestion accepts caller-supplied gate decisions, counts, and scores; it does not independently verify the whole report. The dashboard therefore relies on the report producer's integrity.
- Gitleaks writes its raw report before Python sanitizes it. Failures or timeouts can leave raw data on disk. Its current redaction logic is not a guarantee that credentials never reach disk or other metadata.
- The sample Flask application and vulnerable requirements are intentional scanner fixtures. They were not launched or repaired during this review.
- CLI tool installers and Python dependencies are not fully locked or verified by checksums. A dependency advisory audit and reproducible environment lock remain outstanding; dependency versions were not upgraded as part of this pass.
- The frontend compiled and served successfully, but browser interaction, responsive layouts, and accessibility were not visually tested.
- The gate's automatic aggregation fallback uses a relative import that needs separate coverage for direct script invocation. Input-schema validation also merits further hardening beyond malformed scanner JSON.

This is a source review and local functional validation, not a complete penetration test or production certification.
