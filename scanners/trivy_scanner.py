"""
Trivy Dependency and Docker Image Scanner Wrapper for SecurePipeline.
Handles both filesystem dependency scanning and container image scanning.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securepipeline.scanners.trivy")


def _find_trivy_command() -> Optional[str]:
    """Locate trivy binary in PATH."""
    return shutil.which("trivy")


def _map_severity(raw_severity: str) -> str:
    """Map Trivy severity strings to standard uppercase levels."""
    raw = (raw_severity or "").upper().strip()
    if raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return raw
    if raw in ("UNKNOWN", "NONE"):
        return "INFO"
    return "MEDIUM"


def _parse_trivy_results(
    raw_json_data: Dict[str, Any],
    scanner_name: str,
) -> List[Dict[str, Any]]:
    """Normalizes Trivy JSON results structure into SecurePipeline schema."""
    findings: List[Dict[str, Any]] = []
    results = raw_json_data.get("Results", [])

    for res in results:
        target = res.get("Target", "unknown_target")
        target_type = res.get("Type", "")
        vulnerabilities = res.get("Vulnerabilities", [])

        for vuln in vulnerabilities:
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN_VULN")
            pkg_name = vuln.get("PkgName", "")
            installed_ver = vuln.get("InstalledVersion", "")
            fixed_ver = vuln.get("FixedVersion", "")
            raw_sev = vuln.get("Severity", "UNKNOWN")
            severity = _map_severity(raw_sev)
            title = vuln.get("Title", "")
            desc = vuln.get("Description", "")
            summary = title if title else (desc[:200] + "..." if len(desc) > 200 else desc)

            remediation = ""
            if fixed_ver:
                remediation = f"Upgrade {pkg_name} to version {fixed_ver} or higher."
            else:
                remediation = f"No fixed version currently published for {pkg_name}. Review vendor advisory."

            findings.append({
                "id": vuln_id,
                "scanner": scanner_name,
                "severity": severity,
                "file": target,
                "line": None,
                "description": summary.strip() or f"Vulnerability {vuln_id} in {pkg_name}",
                "remediation": remediation,
                "package": pkg_name,
                "version": installed_ver,
                "raw_details": {
                    "vulnerability_id": vuln_id,
                    "target_type": target_type,
                    "fixed_version": fixed_ver,
                    "primary_url": vuln.get("PrimaryURL", ""),
                    "cwe_ids": vuln.get("CweIDs", []),
                },
            })

    return findings


def run_trivy_fs_scan(
    target_dir: str,
    output_dir: str = "reports/raw",
    timeout_sec: int = 180,
) -> Dict[str, Any]:
    """
    Executes Trivy filesystem / dependency scanning on the target directory.
    """
    binary = _find_trivy_command()
    if not binary:
        return {
            "scanner": "trivy_fs",
            "status": "not_installed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": "Trivy is not installed or not found in PATH.",
            "findings": [],
        }

    os.makedirs(output_dir, exist_ok=True)
    raw_output_path = os.path.join(output_dir, "trivy_fs.json")

    cmd = [
        binary,
        "fs",
        "--format",
        "json",
        "--output",
        raw_output_path,
        target_dir,
    ]

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

        stderr = proc.stderr.strip()

        if proc.returncode != 0:
            return {
                "scanner": "trivy_fs",
                "status": "failed",
                "returncode": proc.returncode,
                "raw_output_path": None,
                "error_message": stderr or f"Trivy fs scan failed with exit code {proc.returncode}.",
                "findings": [],
            }

        if not os.path.isfile(raw_output_path) or os.path.getsize(raw_output_path) == 0:
            raise ValueError("Trivy did not produce a JSON report")
        parsed_json: Dict[str, Any] = {}
        if os.path.exists(raw_output_path) and os.path.getsize(raw_output_path) > 0:
            try:
                with open(raw_output_path, "r", encoding="utf-8") as f:
                    parsed_json = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid Trivy JSON report") from exc
        if not isinstance(parsed_json, dict) or "SchemaVersion" not in parsed_json:
            raise ValueError("Invalid Trivy report schema")

        findings = _parse_trivy_results(parsed_json, "trivy_fs")

        return {
            "scanner": "trivy_fs",
            "status": "success",
            "returncode": proc.returncode,
            "raw_output_path": os.path.abspath(raw_output_path),
            "error_message": None,
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "trivy_fs",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Trivy fs scan timed out after {timeout_sec} seconds.",
            "findings": [],
        }
    except Exception as exc:
        return {
            "scanner": "trivy_fs",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Unexpected error during Trivy fs execution: {str(exc)}",
            "findings": [],
        }


def run_trivy_image_scan(
    image_name: str,
    output_dir: str = "reports/raw",
    timeout_sec: int = 300,
) -> Dict[str, Any]:
    """
    Executes Trivy container image scanning on a built Docker image.
    """
    binary = _find_trivy_command()
    if not binary:
        return {
            "scanner": "trivy_image",
            "status": "not_installed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": "Trivy is not installed or not found in PATH.",
            "findings": [],
        }

    os.makedirs(output_dir, exist_ok=True)
    raw_output_path = os.path.join(output_dir, "trivy_image.json")

    cmd = [
        binary,
        "image",
        "--format",
        "json",
        "--output",
        raw_output_path,
        image_name,
    ]

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

        stderr = proc.stderr.strip()

        if proc.returncode != 0:
            return {
                "scanner": "trivy_image",
                "status": "failed",
                "returncode": proc.returncode,
                "raw_output_path": None,
                "error_message": stderr or f"Trivy image scan failed with exit code {proc.returncode}.",
                "findings": [],
            }

        if not os.path.isfile(raw_output_path) or os.path.getsize(raw_output_path) == 0:
            raise ValueError("Trivy did not produce a JSON report")
        parsed_json: Dict[str, Any] = {}
        if os.path.exists(raw_output_path) and os.path.getsize(raw_output_path) > 0:
            try:
                with open(raw_output_path, "r", encoding="utf-8") as f:
                    parsed_json = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid Trivy JSON report") from exc
        if not isinstance(parsed_json, dict) or "SchemaVersion" not in parsed_json:
            raise ValueError("Invalid Trivy report schema")

        findings = _parse_trivy_results(parsed_json, "trivy_image")

        return {
            "scanner": "trivy_image",
            "status": "success",
            "returncode": proc.returncode,
            "raw_output_path": os.path.abspath(raw_output_path),
            "error_message": None,
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "trivy_image",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Trivy image scan timed out after {timeout_sec} seconds.",
            "findings": [],
        }
    except Exception as exc:
        return {
            "scanner": "trivy_image",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Unexpected error during Trivy image execution: {str(exc)}",
            "findings": [],
        }
