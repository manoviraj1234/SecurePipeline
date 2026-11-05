"""
Semgrep SAST Scanner Wrapper for SecurePipeline.
Runs Semgrep static analysis and captures normalized findings.
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securepipeline.scanners.semgrep")


def _find_semgrep_command() -> Optional[List[str]]:
    """Locate semgrep binary or python module."""
    if shutil.which("semgrep"):
        return ["semgrep"]
    
    # Check if accessible via python -m semgrep
    try:
        res = subprocess.run(
            ["python", "-m", "semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            return ["python", "-m", "semgrep"]
    except Exception:
        pass
    
    return None


def _map_severity(raw_severity: str) -> str:
    """Map Semgrep severity levels to standard levels."""
    raw = (raw_severity or "").upper()
    if raw in ("ERROR", "CRITICAL"):
        return "HIGH"
    if raw in ("WARNING", "WARN"):
        return "MEDIUM"
    if raw in ("INFO", "EXPERIMENT"):
        return "LOW"
    return "MEDIUM"


def run_semgrep_scan(
    target_dir: str,
    output_dir: str = "reports/raw",
    config: str = "auto",
    timeout_sec: int = 180,
) -> Dict[str, Any]:
    """
    Executes Semgrep scanner on the target directory.
    
    Returns:
        dict containing:
            - scanner: 'semgrep'
            - status: 'success' | 'failed' | 'not_installed'
            - returncode: int or None
            - raw_output_path: str or None
            - error_message: str or None
            - findings: list of normalized findings
    """
    cmd_base = _find_semgrep_command()
    if not cmd_base:
        return {
            "scanner": "semgrep",
            "status": "not_installed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": "Semgrep is not installed or not found in PATH.",
            "findings": [],
        }

    os.makedirs(output_dir, exist_ok=True)
    raw_output_path = os.path.join(output_dir, "semgrep.json")
    
    cmd = cmd_base + [
        "scan",
        f"--config={config}",
        "--json",
        "--quiet",
        target_dir,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            shell=False,
        )
        
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        
        # Semgrep returns 0 on success, or 1/2 on specific issues/findings depending on flags
        # Attempt to parse stdout as JSON
        parsed_json: Dict[str, Any] = {}
        if stdout:
            try:
                parsed_json = json.loads(stdout)
            except json.JSONDecodeError as exc:
                logger.error("Failed to decode Semgrep JSON output: %s", exc)

        # Write raw output file
        with open(raw_output_path, "w", encoding="utf-8") as f:
            if parsed_json:
                json.dump(parsed_json, f, indent=2)
            else:
                f.write(stdout or stderr)

        # If we have valid parsed json with results key, it's a successful scan
        if proc.returncode in (0, 1) and isinstance(parsed_json.get("results"), list) and not parsed_json.get("errors"):
            findings: List[Dict[str, Any]] = []
            for item in parsed_json.get("results", []):
                extra = item.get("extra", {})
                metadata = extra.get("metadata", {})
                
                check_id = item.get("check_id", "unknown_rule")
                file_path = item.get("path", "")
                start_line = item.get("start", {}).get("line")
                message = extra.get("message", "").strip()
                severity = _map_severity(extra.get("severity", ""))
                
                # Check for CWE or CVE in metadata
                cwe = metadata.get("cwe", [])
                if isinstance(cwe, list):
                    cwe_str = ", ".join(cwe)
                else:
                    cwe_str = str(cwe) if cwe else ""
                
                remediation = ""
                if metadata.get("fix"):
                    remediation = str(metadata["fix"])
                elif cwe_str:
                    remediation = f"Refer to CWE guidelines: {cwe_str}"
                else:
                    remediation = "Refactor code to resolve rule violation: " + check_id

                findings.append({
                    "id": check_id,
                    "scanner": "semgrep",
                    "severity": severity,
                    "file": file_path,
                    "line": start_line,
                    "description": message,
                    "remediation": remediation,
                    "package": None,
                    "version": None,
                    "raw_details": {
                        "check_id": check_id,
                        "cwe": cwe_str,
                        "owasp": metadata.get("owasp", ""),
                        "category": metadata.get("category", ""),
                    },
                })

            return {
                "scanner": "semgrep",
                "status": "success",
                "returncode": proc.returncode,
                "raw_output_path": os.path.abspath(raw_output_path),
                "error_message": None,
                "findings": findings,
            }

        # If no results key and returncode != 0
        return {
            "scanner": "semgrep",
            "status": "failed",
            "returncode": proc.returncode,
            "raw_output_path": os.path.abspath(raw_output_path),
            "error_message": stderr or "Semgrep exited with non-zero status without valid JSON results.",
            "findings": [],
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "semgrep",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Semgrep scan timed out after {timeout_sec} seconds.",
            "findings": [],
        }
    except Exception as exc:
        return {
            "scanner": "semgrep",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Unexpected error during Semgrep execution: {str(exc)}",
            "findings": [],
        }
