"""
Unified Scanner Manager for SecurePipeline.
Coordinates the execution of SAST, Secrets, SBOM, Dependency, and Image scanners.
Ensures failure of one scanner does not prevent other scanners from running.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from .semgrep_scanner import run_semgrep_scan
    from .gitleaks_scanner import run_gitleaks_scan
    from .syft_scanner import run_syft_scan
    from .trivy_scanner import run_trivy_fs_scan, run_trivy_image_scan
except ImportError:
    from semgrep_scanner import run_semgrep_scan
    from gitleaks_scanner import run_gitleaks_scan
    from syft_scanner import run_syft_scan
    from trivy_scanner import run_trivy_fs_scan, run_trivy_image_scan

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("securepipeline.scanner_manager")


class ScannerManager:
    """Manages and executes all configured security scanners."""

    def __init__(
        self,
        target_dir: str,
        output_dir: str = "reports/raw",
        docker_image: Optional[str] = None,
    ):
        self.target_dir = os.path.abspath(target_dir)
        self.output_dir = os.path.abspath(output_dir)
        self.docker_image = docker_image
        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self, skip_image: bool = False) -> Dict[str, Any]:
        """
        Executes all scanners independently, collecting all results and errors.
        """
        logger.info("Starting security scan on target: %s", self.target_dir)
        start_time = datetime.now(timezone.utc).isoformat()

        scanner_statuses: Dict[str, Any] = {}
        all_findings: List[Dict[str, Any]] = []

        # 1. Semgrep SAST Scan
        logger.info("Executing Semgrep SAST scan...")
        try:
            semgrep_res = run_semgrep_scan(self.target_dir, self.output_dir)
        except Exception as exc:
            logger.error("Unexpected error in Semgrep runner: %s", exc)
            semgrep_res = {
                "scanner": "semgrep",
                "status": "failed",
                "returncode": None,
                "raw_output_path": None,
                "error_message": str(exc),
                "findings": [],
            }
        scanner_statuses["semgrep"] = {
            "status": semgrep_res["status"],
            "returncode": semgrep_res.get("returncode"),
            "raw_output_path": semgrep_res.get("raw_output_path"),
            "error_message": semgrep_res.get("error_message"),
            "findings_count": len(semgrep_res.get("findings", [])),
        }
        all_findings.extend(semgrep_res.get("findings", []))

        # 2. Gitleaks Secret Detection Scan
        logger.info("Executing Gitleaks secret detection...")
        try:
            gitleaks_res = run_gitleaks_scan(self.target_dir, self.output_dir)
        except Exception as exc:
            logger.error("Unexpected error in Gitleaks runner: %s", exc)
            gitleaks_res = {
                "scanner": "gitleaks",
                "status": "failed",
                "returncode": None,
                "raw_output_path": None,
                "error_message": str(exc),
                "findings": [],
            }
        scanner_statuses["gitleaks"] = {
            "status": gitleaks_res["status"],
            "returncode": gitleaks_res.get("returncode"),
            "raw_output_path": gitleaks_res.get("raw_output_path"),
            "error_message": gitleaks_res.get("error_message"),
            "findings_count": len(gitleaks_res.get("findings", [])),
        }
        all_findings.extend(gitleaks_res.get("findings", []))

        # 3. Syft SBOM Generation
        logger.info("Executing Syft SBOM generation...")
        try:
            syft_res = run_syft_scan(self.target_dir, self.output_dir)
        except Exception as exc:
            logger.error("Unexpected error in Syft runner: %s", exc)
            syft_res = {
                "scanner": "syft",
                "status": "failed",
                "returncode": None,
                "raw_output_path": None,
                "error_message": str(exc),
                "findings": [],
                "artifact_count": 0,
            }
        scanner_statuses["syft"] = {
            "status": syft_res["status"],
            "returncode": syft_res.get("returncode"),
            "raw_output_path": syft_res.get("raw_output_path"),
            "error_message": syft_res.get("error_message"),
            "artifact_count": syft_res.get("artifact_count", 0),
        }
        all_findings.extend(syft_res.get("findings", []))

        # 4. Trivy Filesystem Dependency Scan
        logger.info("Executing Trivy dependency scan...")
        try:
            trivy_fs_res = run_trivy_fs_scan(self.target_dir, self.output_dir)
        except Exception as exc:
            logger.error("Unexpected error in Trivy FS runner: %s", exc)
            trivy_fs_res = {
                "scanner": "trivy_fs",
                "status": "failed",
                "returncode": None,
                "raw_output_path": None,
                "error_message": str(exc),
                "findings": [],
            }
        scanner_statuses["trivy_fs"] = {
            "status": trivy_fs_res["status"],
            "returncode": trivy_fs_res.get("returncode"),
            "raw_output_path": trivy_fs_res.get("raw_output_path"),
            "error_message": trivy_fs_res.get("error_message"),
            "findings_count": len(trivy_fs_res.get("findings", [])),
        }
        all_findings.extend(trivy_fs_res.get("findings", []))

        # 5. Trivy Docker Image Scan (if requested and Dockerfile/image specified)
        if self.docker_image and not skip_image:
            logger.info("Executing Trivy Docker image scan for: %s", self.docker_image)
            try:
                trivy_img_res = run_trivy_image_scan(self.docker_image, self.output_dir)
            except Exception as exc:
                logger.error("Unexpected error in Trivy Image runner: %s", exc)
                trivy_img_res = {
                    "scanner": "trivy_image",
                    "status": "failed",
                    "returncode": None,
                    "raw_output_path": None,
                    "error_message": str(exc),
                    "findings": [],
                }
            scanner_statuses["trivy_image"] = {
                "status": trivy_img_res["status"],
                "returncode": trivy_img_res.get("returncode"),
                "raw_output_path": trivy_img_res.get("raw_output_path"),
                "error_message": trivy_img_res.get("error_message"),
                "findings_count": len(trivy_img_res.get("findings", [])),
            }
            all_findings.extend(trivy_img_res.get("findings", []))
        else:
            scanner_statuses["trivy_image"] = {
                "status": "skipped",
                "returncode": None,
                "raw_output_path": None,
                "error_message": "Docker image not specified or image scan was skipped.",
                "findings_count": 0,
            }

        end_time = datetime.now(timezone.utc).isoformat()

        manifest = {
            "scan_metadata": {
                "target_directory": self.target_dir,
                "start_time": start_time,
                "end_time": end_time,
                "docker_image": self.docker_image,
            },
            "scanner_statuses": scanner_statuses,
            "total_raw_findings": len(all_findings),
            "findings": all_findings,
        }

        manifest_path = os.path.join(self.output_dir, "scan_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        logger.info(
            "Security scan complete. Raw findings: %d. Manifest written to: %s",
            len(all_findings),
            manifest_path,
        )
        return manifest


def main():
    parser = argparse.ArgumentParser(description="SecurePipeline Scanner Manager CLI")
    parser.add_argument(
        "--target",
        "-t",
        default=".",
        help="Target directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="reports/raw",
        help="Directory to save raw scan reports",
    )
    parser.add_argument(
        "--image",
        "-i",
        default=None,
        help="Docker image tag to scan (optional)",
    )
    parser.add_argument(
        "--skip-image",
        action="store_true",
        help="Skip container image scanning",
    )

    args = parser.parse_args()
    manager = ScannerManager(
        target_dir=args.target,
        output_dir=args.output,
        docker_image=args.image,
    )
    result = manager.run_all(skip_image=args.skip_image)
    print(json.dumps(result["scanner_statuses"], indent=2))


if __name__ == "__main__":
    main()
