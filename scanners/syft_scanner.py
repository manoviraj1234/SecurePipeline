"""
Syft SBOM Generator Wrapper for SecurePipeline.
Generates Software Bill of Materials (SBOM) in standard JSON format.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securepipeline.scanners.syft")


def _find_syft_command() -> Optional[str]:
    """Locate syft binary in PATH."""
    return shutil.which("syft")


def run_syft_scan(
    target_dir: str,
    output_dir: str = "reports/raw",
    timeout_sec: int = 180,
) -> Dict[str, Any]:
    """
    Executes Syft SBOM generation on the target directory.
    
    Returns:
        dict containing:
            - scanner: 'syft'
            - status: 'success' | 'failed' | 'not_installed'
            - returncode: int or None
            - raw_output_path: str or None
            - error_message: str or None
            - findings: list (empty or informational inventory items)
            - artifact_count: int
    """
    binary = _find_syft_command()
    if not binary:
        return {
            "scanner": "syft",
            "status": "not_installed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": "Syft is not installed or not found in PATH.",
            "findings": [],
            "artifact_count": 0,
        }

    os.makedirs(output_dir, exist_ok=True)
    raw_output_path = os.path.join(output_dir, "syft_sbom.json")

    cmd = [
        binary,
        f"dir:{target_dir}",
        "-o",
        "json",
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

        if proc.returncode != 0:
            return {
                "scanner": "syft",
                "status": "failed",
                "returncode": proc.returncode,
                "raw_output_path": None,
                "error_message": stderr or f"Syft execution failed with exit code {proc.returncode}.",
                "findings": [],
                "artifact_count": 0,
            }

        # Save raw output
        with open(raw_output_path, "w", encoding="utf-8") as f:
            f.write(stdout)

        # Parse SBOM JSON
        parsed_sbom: Dict[str, Any] = {}
        try:
            parsed_sbom = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid Syft JSON report") from exc
        if not isinstance(parsed_sbom, dict) or not isinstance(parsed_sbom.get("artifacts"), list):
            raise ValueError("Invalid Syft report schema")

        artifacts = parsed_sbom.get("artifacts", [])
        artifact_count = len(artifacts)

        return {
            "scanner": "syft",
            "status": "success",
            "returncode": proc.returncode,
            "raw_output_path": os.path.abspath(raw_output_path),
            "error_message": None,
            "findings": [],  # Syft creates an inventory; Trivy evaluates vulnerabilities
            "artifact_count": artifact_count,
            "schema_version": parsed_sbom.get("schema", {}).get("version", "unknown"),
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "syft",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Syft execution timed out after {timeout_sec} seconds.",
            "findings": [],
            "artifact_count": 0,
        }
    except Exception as exc:
        return {
            "scanner": "syft",
            "status": "failed",
            "returncode": None,
            "raw_output_path": None,
            "error_message": f"Unexpected error during Syft execution: {str(exc)}",
            "findings": [],
            "artifact_count": 0,
        }
