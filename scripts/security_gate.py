"""
Intelligent Security Gate for SecurePipeline.
Enforces fail-closed security policies based on findings and scanner execution health.
Decisions:
  - PASS (exit 0): All required scans completed successfully, no blocking findings.
  - BLOCK (exit 1): Scans completed, but critical/high vulnerabilities detected.
  - INCOMPLETE (exit 2): One or more scans failed, were skipped, or had errors.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [security_gate]: %(message)s",
)
logger = logging.getLogger("securepipeline.security_gate")

REQUIRED_SCANNERS_BASE = ["semgrep", "gitleaks", "syft", "trivy_fs"]


def calculate_security_score(
    severity_counts: Dict[str, int],
    is_scan_complete: bool,
) -> Dict[str, Any]:
    """
    Calculates a transparent, documented security score from 0 to 100.
    Base score: 100
    Deductions:
      - Critical: -25 pts
      - High:     -15 pts
      - Medium:   -5 pts
      - Low:      -1 pt
    Floor: 0.
    If the scan is INCOMPLETE, the score is explicitly flagged as unverified/unavailable.
    """
    crit = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    med = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)

    deductions = (crit * 25) + (high * 15) + (med * 5) + (low * 1)
    provisional = max(0, 100 - deductions)

    if not is_scan_complete:
        return {
            "score": None,
            "provisional_score": provisional,
            "status": "UNAVAILABLE_INCOMPLETE_SCAN",
            "formula": "Base (100) - (Critical*25 + High*15 + Medium*5 + Low*1)",
            "explanation": "Security score cannot be certified because one or more required scans were incomplete or failed.",
        }

    return {
        "score": provisional,
        "provisional_score": provisional,
        "status": "VERIFIED",
        "formula": "Base (100) - (Critical*25 + High*15 + Medium*5 + Low*1)",
        "explanation": f"Score calculated based on 100 base points minus {deductions} deduction points across verified findings.",
    }


def evaluate_security_gate(
    aggregated_path: str = "reports/aggregated_findings.json",
    manifest_path: Optional[str] = None,
    output_path: str = "reports/security_gate.json",
    block_severities: Optional[List[str]] = None,
    require_image_scan: bool = False,
) -> Tuple[str, int, Dict[str, Any]]:
    """
    Evaluates the security gate policy.
    
    Returns:
        (decision_str, exit_code, gate_report_dict)
    """
    if block_severities is None:
        block_severities = ["CRITICAL", "HIGH"]
    block_severities = [s.upper().strip() for s in block_severities]

    aggregated_data: Dict[str, Any] = {}
    if os.path.exists(aggregated_path):
        try:
            with open(aggregated_path, "r", encoding="utf-8") as f:
                aggregated_data = json.load(f)
        except Exception as exc:
            logger.error("Failed to parse aggregated findings: %s", exc)
            return _build_incomplete_response(
                output_path=output_path,
                reason=f"Aggregated findings file at '{aggregated_path}' is corrupted or unreadable: {exc}",
                block_severities=block_severities,
            )
    else:
        # Check if manifest exists to aggregate on the fly
        manifest_to_check = manifest_path or "reports/raw/scan_manifest.json"
        if os.path.exists(manifest_to_check):
            from .aggregate import aggregate_findings
            try:
                aggregated_data = aggregate_findings(
                    manifest_path=manifest_to_check,
                    output_path=aggregated_path,
                )
            except Exception as exc:
                return _build_incomplete_response(
                    output_path=output_path,
                    reason=f"Could not automatically aggregate manifest '{manifest_to_check}': {exc}",
                    block_severities=block_severities,
                )
        else:
            return _build_incomplete_response(
                output_path=output_path,
                reason=f"Neither aggregated findings ('{aggregated_path}') nor manifest ('{manifest_to_check}') found.",
                block_severities=block_severities,
            )

    scanner_statuses = aggregated_data.get("scanner_statuses", {})
    metadata = aggregated_data.get("metadata", {})
    findings = aggregated_data.get("findings", [])
    severity_counts = aggregated_data.get("severity_counts", {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    })

    # Determine required scanners list
    required_scanners = list(REQUIRED_SCANNERS_BASE)
    # If Docker image was provided in metadata or require_image_scan is true
    docker_image = metadata.get("docker_image")
    if docker_image or require_image_scan:
        required_scanners.append("trivy_image")

    # Step 1: Check Scanner Execution Health
    incomplete_reasons = []
    for sc in required_scanners:
        if sc not in scanner_statuses:
            incomplete_reasons.append(f"Required scanner '{sc}' was not present in scan execution manifest.")
            continue
        sc_info = scanner_statuses[sc]
        sc_status = sc_info.get("status")
        if sc_status != "success":
            err_msg = sc_info.get("error_message") or f"returned status '{sc_status}'"
            incomplete_reasons.append(f"Scanner '{sc}' did not complete successfully: {err_msg}")

    # If any required scanner failed or was missing, gate is INCOMPLETE (Fail-closed)
    if incomplete_reasons:
        logger.warning("Security Gate evaluated as INCOMPLETE due to scanner failures: %s", incomplete_reasons)
        score_info = calculate_security_score(severity_counts, is_scan_complete=False)
        gate_result = {
            "decision": "INCOMPLETE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "blocking_severities": block_severities,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "scanner_statuses": scanner_statuses,
            "blocking_findings": [],
            "warnings": incomplete_reasons,
            "explanation": "Security gate failed closed: one or more required security scanners did not execute successfully. Deployment blocked.",
            "security_score": score_info["score"],
            "score_details": score_info,
        }
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(gate_result, f, indent=2)
        return ("INCOMPLETE", 2, gate_result)

    # Step 2: Check for Blocking Findings
    blocking_findings = []
    warnings = []
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        if sev in block_severities:
            blocking_findings.append(f)
        else:
            if sev in ("MEDIUM", "LOW"):
                warnings.append(f"Allowed finding ({sev}): [{f.get('id')}] in {f.get('file') or f.get('package') or 'codebase'}")

    score_info = calculate_security_score(severity_counts, is_scan_complete=True)

    if blocking_findings:
        decision = "BLOCK"
        exit_code = 1
        explanation = f"Security gate BLOCKED deployment: {len(blocking_findings)} blocking vulnerabilities detected ({', '.join(block_severities)})."
        logger.warning(explanation)
    else:
        decision = "PASS"
        exit_code = 0
        explanation = "Security gate PASSED: All required scanners executed successfully and zero blocking vulnerabilities detected."
        logger.info(explanation)

    gate_result = {
        "decision": decision,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "blocking_severities": block_severities,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "scanner_statuses": scanner_statuses,
        "blocking_findings": blocking_findings,
        "warnings": warnings,
        "explanation": explanation,
        "security_score": score_info["score"],
        "score_details": score_info,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(gate_result, f, indent=2)

    return (decision, exit_code, gate_result)


def _build_incomplete_response(
    output_path: str,
    reason: str,
    block_severities: List[str],
) -> Tuple[str, int, Dict[str, Any]]:
    """Helper to write fail-closed INCOMPLETE decision on unhandled file or parse errors."""
    score_info = calculate_security_score({}, is_scan_complete=False)
    gate_result = {
        "decision": "INCOMPLETE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "blocking_severities": block_severities,
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "scanner_statuses": {},
        "blocking_findings": [],
        "warnings": [reason],
        "explanation": f"Security gate failed closed: {reason}. Deployment blocked.",
        "security_score": None,
        "score_details": score_info,
    }
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(gate_result, f, indent=2)
    return ("INCOMPLETE", 2, gate_result)


def main():
    parser = argparse.ArgumentParser(description="SecurePipeline Security Gate Evaluator")
    parser.add_argument("--aggregated", default="reports/aggregated_findings.json", help="Path to aggregated findings JSON")
    parser.add_argument("--manifest", default="reports/raw/scan_manifest.json", help="Path to raw scan manifest JSON")
    parser.add_argument("--output", default="reports/security_gate.json", help="Output path for security gate decision JSON")
    parser.add_argument("--block-severities", default="CRITICAL,HIGH", help="Comma-separated severities that block (default: CRITICAL,HIGH)")
    parser.add_argument("--require-image-scan", action="store_true", help="Enforce container image scan completion")

    args = parser.parse_args()
    block_list = [s.strip() for s in args.block_severities.split(",") if s.strip()]

    try:
        decision, code, result = evaluate_security_gate(
            aggregated_path=args.aggregated,
            manifest_path=args.manifest,
            output_path=args.output,
            block_severities=block_list,
            require_image_scan=args.require_image_scan,
        )
        print(f"\n=======================================================")
        print(f" [SECURE PIPELINE GATE DECISION]: {decision}")
        print(f" Exit Code: {code}")
        print(f" {result['explanation']}")
        if result["warnings"]:
            print(f" Warnings / Diagnostics: {len(result['warnings'])}")
            for w in result["warnings"][:5]:
                print(f"  - {w}")
        print(f"=======================================================\n")
        sys.exit(code)
    except Exception as exc:
        logger.error("Internal error in security gate execution: %s", exc)
        sys.exit(3)


if __name__ == "__main__":
    main()
