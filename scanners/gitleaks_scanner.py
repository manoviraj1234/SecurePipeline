"""
Gitleaks Secret Detection Scanner Wrapper for SecurePipeline.
Detects hardcoded secrets, API keys, and credentials, redacting raw secrets.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securepipeline.scanners.gitleaks")


def _find_gitleaks_command() -> Optional[str]:
    """Locate gitleaks binary in PATH."""
    return shutil.which("gitleaks")


def _redact_secret_value(value: Optional[str]) -> str:
    """Redact secret string so raw secrets are never exposed in logs or reports."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***REDACTED***"
    # Show only the first 2 and last 2 characters for debugging/triage without exposure
    return f"{value[:2]}***REDACTED***{value[-2:]}"


def run_gitleaks_scan(
    target_dir: str,
    output_dir: str = "reports/raw",
    timeout_sec: int = 120,
) -> Dict[str, Any]:
    """
    Executes Gitleaks secret detection scanner on the target directory.
    
    Returns:
        dict containing:
            - scanner: 'gitleaks'
            - status: 'success' | 'failed' | 'not_installed'
            - returncode: int or None
            - raw_output_path: str or None
            - error_message: str or None
            - findings: list of normalized findings
    """
    binary = _find_gitleaks_command()
    if not binary:
        return {
            "scanner": "gitleaks",
            "status": "not_installed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": "Gitleaks is not installed or not found in PATH.",
            "findings": [],
        }

    os.makedirs(output_dir, exist_ok=True)
    raw_output_path = os.path.join(output_dir, "gitleaks.json")

    # If target has .git directory, run standard detect; otherwise use --no-git
    git_dir = os.path.join(target_dir, ".git")
    cmd = [
        binary,
        "detect",
        f"--source={target_dir}",
        "--report-format=json",
        f"--report-path={raw_output_path}",
    ]
    if not os.path.exists(git_dir):
        cmd.append("--no-git")

    try:
        if os.path.exists(raw_output_path):
            os.remove(raw_output_path)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            shell=False,
        )

        # Gitleaks exit codes:
        # 0 = No leaks found
        # 1 = Leaks detected (Scan succeeded!)
        # Any other exit code = Error during execution
        if proc.returncode not in (0, 1):
            stderr = proc.stderr.strip()
            return {
                "scanner": "gitleaks",
                "status": "failed",
                "returncode": proc.returncode,
                "raw_output_path": os.path.abspath(raw_output_path) if os.path.exists(raw_output_path) else None,
                "error_message": stderr or f"Gitleaks execution failed with exit code {proc.returncode}.",
                "findings": [],
            }

        findings: List[Dict[str, Any]] = []
        raw_entries: List[Dict[str, Any]] = []

        if not os.path.isfile(raw_output_path) or os.path.getsize(raw_output_path) == 0:
            raise ValueError("Gitleaks did not produce a JSON report")
        if os.path.exists(raw_output_path) and os.path.getsize(raw_output_path) > 0:
            try:
                with open(raw_output_path, "r", encoding="utf-8") as f:
                    raw_entries = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid Gitleaks JSON report") from exc
        if not isinstance(raw_entries, list):
            raise ValueError("Invalid Gitleaks report schema")

        # Sanitize raw entries in file to guarantee secrets are NEVER stored on disk
        sanitized_entries = []
        for entry in raw_entries:
            rule_id = entry.get("RuleID", "generic-secret")
            desc = entry.get("Description", "Potential secret detected")
            file_path = entry.get("File", "")
            start_line = entry.get("StartLine")
            secret_val = entry.get("Secret", "")
            redacted_secret = _redact_secret_value(secret_val)

            sanitized_entry = dict(entry)
            sanitized_entry["Secret"] = redacted_secret
            sanitized_entry["Match"] = _redact_secret_value(entry.get("Match", ""))
            sanitized_entries.append(sanitized_entry)

            findings.append({
                "id": rule_id,
                "scanner": "gitleaks",
                "severity": "HIGH",  # Hardcoded secrets are high/critical severity in CI/CD
                "file": file_path,
                "line": start_line,
                "description": f"{desc} (Rule: {rule_id})",
                "remediation": "Revoke the exposed credential immediately and replace it with environment variables or a secrets manager.",
                "package": None,
                "version": None,
                "raw_details": {
                    "rule_id": rule_id,
                    "entropy": entry.get("Entropy"),
                    "commit": entry.get("Commit"),
                    "redacted_sample": redacted_secret,
                },
            })

        # Overwrite raw output with redacted entries for strict compliance
        with open(raw_output_path, "w", encoding="utf-8") as f:
            json.dump(sanitized_entries, f, indent=2)

        return {
            "scanner": "gitleaks",
            "status": "success",
            "returncode": proc.returncode,
            "raw_output_path": os.path.abspath(raw_output_path),
            "error_message": None,
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "gitleaks",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Gitleaks scan timed out after {timeout_sec} seconds.",
            "findings": [],
        }
    except Exception as exc:
        return {
            "scanner": "gitleaks",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Unexpected error during Gitleaks execution: {str(exc)}",
            "findings": [],
        }
