# SecurePipeline Architecture Documentation

## Overview
SecurePipeline is a DevSecOps automation framework that injects security testing directly into the CI/CD pipeline.  When developers push code, a GitHub Actions workflow runs a set of open‑source scanners, aggregates the findings, and decides whether the build can continue.  All results are stored in a SQLite database and visualised through a lightweight FastAPI‑driven React dashboard.

## Components
| Component | Responsibility |
|-----------|----------------|
| **GitHub Actions workflow** (`.github/workflows/security.yml`) | Orchestrates checkout, scanner installation, parallel execution of security tools, aggregation, security‑gate evaluation, Docker image build (optional) and final report upload. |
| **Scanners** (`scanners/` package) | Python wrappers around **Semgrep**, **Gitleaks**, **Syft**, and **Trivy**. Each wrapper executes the CLI via `subprocess`, captures JSON output, and normalises it to a common schema. |
| **Aggregation script** (`scripts/aggregate.py`) | Merges individual scanner outputs, de‑duplicates findings, and writes `report.json`. |
| **Security gate** (`scripts/security_gate.py`) | Reads the aggregated report, applies severity‑based blocking rules (CRITICAL/HIGH block, MEDIUM/LOW allow), produces `report.html`, and exits with a non‑zero status when a block is required. |
| **FastAPI backend** (`dashboard/backend/`) | Provides REST endpoints (`/api/reports`, `/api/dashboard/summary`, `/api/vulnerabilities`, …) that store findings in a SQLite database and expose them to the UI. |
| **React dashboard** (`dashboard/frontend/`) | Consumes the FastAPI API, displays a summary card, severity distribution chart, vulnerability table, and details page. All data is live – there are no hard‑coded numbers. |
| **SQLite database** | Simple file‑based store (`backend.db`) used by the FastAPI service; sufficient for a demo and works on both Windows and Linux runners. |
| **AI explanation module** (`scripts/ai_explain.py`, optional) | Generates short remediation suggestions using Gemini‑Pro (free tier). This module is optional and is not part of the core blocking logic. |

## Data Flow
1. **Push/PR** triggers the GitHub Actions workflow.
2. Workflow **installs** the required CLI tools (Semgrep, Gitleaks, Syft, Trivy).
3. Each scanner runs in parallel, outputting JSON files to the workspace.
4. `scripts/aggregate.py` reads all JSON files, normalises the schema, removes duplicates, and writes `report.json`.
5. `scripts/security_gate.py` evaluates the aggregated report against severity rules. If a blocking vulnerability is present, the job **fails** but still uploads `report.json` and `report.html` as artifacts.
6. If the gate passes, the workflow optionally **builds a Docker image** and runs a **Trivy image scan** before the final decision.
7. The final report (JSON + HTML) is posted to the FastAPI backend via the `POST /api/reports` endpoint.
8. The backend stores each finding in SQLite and exposes read‑only endpoints used by the React dashboard.

## Key Adjustments (per your request)
- **Artifacts uploaded regardless of outcome** – the workflow always uploads `report.json`/`report.html` even when the build is blocked.
- **Scanner failures are distinguished** – if a scanner exits with an error, the aggregation step records a special entry (`"scanner_error": true`) but does not treat it as a clean pass.
- **Docker image scan occurs before the final deployment decision** – the image is built after the gate passes and then scanned; a failing image scan also triggers a block.
- **Gitleaks** replaces TruffleHog for secret detection.
- **Trivy** handles both dependency scanning (via the generated SBOM) and container image scanning.
- **SQLite** is the chosen lightweight DB for the dashboard.
- **No hard‑coded data** – the dashboard UI fetches live data from the FastAPI backend.
- **Optional AI explanations** are decoupled from the gate logic to avoid slowing down the core pipeline.

## Implementation Status
Phases 1–7 are implemented: scanner wrappers, aggregation, the fail-closed security gate, GitHub Actions, the FastAPI service, SQLite, and the React dashboard. Later additions score each finding by contextual risk, compare consecutive scans for regressions, and attach a concrete remediation snippet in the dashboard.

---
*This document is version‑controlled and will be expanded as the implementation progresses.*
