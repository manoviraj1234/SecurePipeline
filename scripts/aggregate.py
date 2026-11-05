"""
Findings Aggregator for SecurePipeline.
Normalizes findings across Semgrep, Gitleaks, Syft, and Trivy.
Handles deduplication, missing tools, and schema standardization.
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [aggregator]: %(message)s",
)
logger = logging.getLogger("securepipeline.aggregator")

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def compute_fingerprint(scanner: str, finding_id: str, file_path: Optional[str], line: Optional[int], package: Optional[str]) -> str:
    """Computes a deterministic SHA-256 fingerprint for finding deduplication."""
    norm_scanner = (scanner or "").strip().lower()
    norm_id = (finding_id or "").strip().lower()
    norm_file = (file_path or "").replace("\\", "/").strip().lower()
    norm_line = str(line or 0)
    norm_pkg = (package or "").strip().lower()

    raw_key = f"{norm_scanner}:{norm_id}:{norm_file}:{norm_line}:{norm_pkg}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]


def normalize_severity(severity: Optional[str]) -> str:
    """Normalizes severity strings to standard uppercase levels."""
    if not severity:
        return "MEDIUM"
    sev = str(severity).strip().upper()
    if sev in VALID_SEVERITIES:
        return sev
    if sev in ("ERROR", "FATAL"):
        return "HIGH"
    if sev in ("WARNING", "WARN"):
        return "MEDIUM"
    if sev in ("NOTE", "NOTICE"):
        return "LOW"
    return "INFO"


def extract_sbom_inventory(raw_dir: str) -> Dict[str, Any]:
    """
    Safely reads Syft SBOM output from raw reports.
    Preserves software component inventory without treating packages as vulnerabilities.
    """
    syft_path = os.path.join(raw_dir, "syft_sbom.json")
    if not os.path.exists(syft_path):
        return {"total_packages": 0, "packages": [], "status": "not_found"}

    try:
        with open(syft_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logger.warning("Could not read or parse syft_sbom.json: %s", exc)
        return {"total_packages": 0, "packages": [], "status": "parse_error", "error": str(exc)}

    artifacts = data.get("artifacts", [])
    packages = []
    for art in artifacts:
        locations = [loc.get("path") for loc in art.get("locations", []) if isinstance(loc, dict) and loc.get("path")]
        packages.append({
            "name": art.get("name"),
            "version": art.get("version"),
            "type": art.get("type"),
            "locations": locations,
            "licenses": art.get("licenses", []),
            "purl": art.get("purl"),
        })

    return {
        "total_packages": len(packages),
        "packages": packages,
        "status": "success",
    }


def normalize_raw_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes any raw scanner finding into the standard SecurePipeline schema:
    - id
    - scanner
    - severity
    - title
    - description
    - file
    - line
    - package
    - installed_version
    - fixed_version
    - remediation
    - references
    - fingerprint
    """
    scanner = finding.get("scanner", "unknown")
    finding_id = finding.get("id") or finding.get("VulnerabilityID") or finding.get("RuleID") or "UNKNOWN_ID"
    severity = normalize_severity(finding.get("severity") or finding.get("Severity"))
    
    file_path = finding.get("file") or finding.get("File") or finding.get("Target")
    line = finding.get("line") or finding.get("StartLine")
    if line is not None:
        try:
            line = int(line)
        except (ValueError, TypeError):
            line = None

    package = finding.get("package") or finding.get("PkgName")
    installed_version = finding.get("version") or finding.get("InstalledVersion")
    
    raw_details = finding.get("raw_details") or {}
    fixed_version = raw_details.get("fixed_version") or finding.get("FixedVersion")
    
    description = finding.get("description") or finding.get("Description") or finding.get("Title") or ""
    title = finding.get("title") or finding.get("Title") or (description[:80] + "..." if len(description) > 80 else description)
    remediation = finding.get("remediation") or finding.get("Remediation")

    # References
    references = []
    if raw_details.get("primary_url"):
        references.append(raw_details["primary_url"])
    if raw_details.get("cwe"):
        references.append(f"CWE: {raw_details['cwe']}")
    if raw_details.get("owasp"):
        references.append(f"OWASP: {raw_details['owasp']}")
    if finding.get("PrimaryURL"):
        references.append(finding["PrimaryURL"])

    fp = compute_fingerprint(scanner, finding_id, file_path, line, package)

    return {
        "id": finding_id,
        "scanner": scanner,
        "severity": severity,
        "title": title.strip() if title else None,
        "description": description.strip(),
        "file": file_path.replace("\\", "/") if file_path else None,
        "line": line,
        "package": package,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "remediation": remediation.strip() if remediation else None,
        "references": references,
        "fingerprint": fp,
    }


def aggregate_findings(
    raw_dir: str = "reports/raw",
    manifest_path: Optional[str] = None,
    output_path: str = "reports/aggregated_findings.json",
) -> Dict[str, Any]:
    """
    Main aggregation function.
    Reads manifest and raw outputs, standardizes findings, deduplicates, and extracts SBOM.
    """
    raw_dir = os.path.abspath(raw_dir)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if not manifest_path:
        manifest_path = os.path.join(raw_dir, "scan_manifest.json")

    manifest_data: Dict[str, Any] = {}
    scanner_statuses: Dict[str, Any] = {}
    aggregation_errors: List[str] = []

    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            scanner_statuses = manifest_data.get("scanner_statuses", {})
        except Exception as exc:
            err = f"Failed to parse scan manifest at {manifest_path}: {exc}"
            logger.error(err)
            aggregation_errors.append(err)
    else:
        err = f"Scan manifest not found at {manifest_path}"
        logger.warning(err)
        aggregation_errors.append(err)

    # Collect raw findings from manifest and from disk
    raw_findings: List[Dict[str, Any]] = []
    if "findings" in manifest_data and isinstance(manifest_data["findings"], list):
        raw_findings.extend(manifest_data["findings"])

    # Deduplicate findings using fingerprint
    seen_fingerprints: Set[str] = set()
    normalized_findings: List[Dict[str, Any]] = []

    for item in raw_findings:
        norm = normalize_raw_finding(item)
        fp = norm["fingerprint"]
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            normalized_findings.append(norm)

    # Calculate severity counts
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    for f in normalized_findings:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["INFO"] += 1

    # Extract SBOM packages
    sbom_inventory = extract_sbom_inventory(raw_dir)

    result = {
        "aggregated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": manifest_data.get("scan_metadata", {}),
        "scanner_statuses": scanner_statuses,
        "total_findings": len(normalized_findings),
        "severity_counts": severity_counts,
        "findings": normalized_findings,
        "sbom": {
            "total_packages": sbom_inventory.get("total_packages", 0),
            "status": sbom_inventory.get("status"),
            "packages": sbom_inventory.get("packages", []),
        },
        "aggregation_errors": aggregation_errors,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    logger.info("Aggregated %d findings. Output saved to %s", len(normalized_findings), output_path)
    return result


def main():
    parser = argparse.ArgumentParser(description="SecurePipeline Findings Aggregator")
    parser.add_argument("--raw-dir", default="reports/raw", help="Directory containing raw scan files")
    parser.add_argument("--manifest", default=None, help="Path to scan_manifest.json")
    parser.add_argument("--output", default="reports/aggregated_findings.json", help="Path to write aggregated findings JSON")

    args = parser.parse_args()
    res = aggregate_findings(
        raw_dir=args.raw_dir,
        manifest_path=args.manifest,
        output_path=args.output,
    )
    print(f"Aggregation complete. Total findings: {res['total_findings']}")


if __name__ == "__main__":
    main()
