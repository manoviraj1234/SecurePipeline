# Before/after security demonstration

The original scan of commit `9060b0b` blocked deployment with 80 HIGH/CRITICAL
findings, across 271 total findings. The report and raw scanner files are
preserved locally under ignored `logs/before-block/` and in the GitHub artifact:

https://github.com/manoviraj1234/SecurePipeline/actions/runs/42038440182

Blocking findings comprised 10 Semgrep findings, 2 Gitleaks findings, 11 Trivy
filesystem findings, and 57 Trivy image findings. Some represented the same
dependency in source and container contexts; these are findings, not necessarily
80 unique underlying vulnerabilities.

## Changes to the deployed application

- Removed the dummy credential from the deployed app.
- Replaced user-controlled subprocess execution with fixed Python diagnostic
  operations. No system process is launched by an API request.
- Replaced Python expression execution with JSON parsing, a 4096-character
  limit, and an explicit nesting limit of 32.
- Removed unused requests/urllib3 dependencies and pinned the Flask runtime,
  Gunicorn, and their dependencies to releases checked against PyPI.
- Replaced the Debian-based image with an updated Alpine-based Python image;
  the built image still undergoes Trivy scanning. No OS findings were ignored.
- Added a non-root runtime user and Gunicorn rather than Flask's development
  server.
- Moved alternate demo source/dependency files into test fixtures. Previously,
  the deployed source directory contained both hardened and deliberately
  vulnerable variants, so it could never represent a clean application. The
  workflow still scans all of `sample_app/` and its container. The test fixtures
  remain available and versioned; the project does not claim the entire
  repository, including intentional vulnerability fixtures, is vulnerability-free.

The HIGH/CRITICAL thresholds and required scanner checks were not changed.
No allowlist, ignore-unfixed flag, or suppressed vulnerability was introduced.

## Verification

The initial hardened commit `b4572e2` passed the real GitHub workflow:

https://github.com/manoviraj1234/SecurePipeline/actions/runs/42039358300

The follow-up commit `38d32e2` adds the explicit JSON nesting limit and also passed:

https://github.com/manoviraj1234/SecurePipeline/actions/runs/42039551356

All five scanners succeeded. The final report contains zero CRITICAL/HIGH,
five MEDIUM, and one LOW finding. All six remaining findings are in the container
image. The security score is 74 and the gate decision is PASS; the deployment
approval job succeeded. These results do not imply zero vulnerabilities.

The root suite passes 31 tests, including six new sample-app regressions. Flask and its
dependencies were installed in ignored `logs/test-deps/` for local validation;
the global Python installation was not changed. The 43 backend tests were rerun
and passed too: 74 tests passed in total.

Run the root tests in a Python environment with root requirements installed, or
set `PYTHONPATH` to the absolute `logs/test-deps` directory in this workspace.

The dashboard now includes the actual original BLOCK report as scan ID 2 and
the final PASS report as scan ID 3, in addition to its original bundled demo.
The final report and raw files are preserved under ignored `logs/after-pass/`.
Historical bundled reports elsewhere in
the repository remain historical examples, not evidence of the current build.

A passing gate means the configured scanners completed and found no blocking
findings at scan time. It does not establish that the application has no security
issues or replace a production security review.
