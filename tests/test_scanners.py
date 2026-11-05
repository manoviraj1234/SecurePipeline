"""
Comprehensive Tests for SecurePipeline Scanner Integration.
Validates safe execution, missing tool handling, parsing, and secret redaction.
"""

import json
import os
import sys
import tempfile
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanners.semgrep_scanner import run_semgrep_scan, _map_severity as semgrep_map_severity
from scanners.gitleaks_scanner import run_gitleaks_scan, _redact_secret_value
from scanners.syft_scanner import run_syft_scan
from scanners.trivy_scanner import run_trivy_fs_scan, run_trivy_image_scan, _parse_trivy_results
from scanners.scanner_manager import ScannerManager


class TestScannerWrappers(unittest.TestCase):
    def setUp(self):
        self.target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_app"))
        self.output_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.output_temp.cleanup)
        self.output_dir = self.output_temp.name

    def test_semgrep_scanner_contract(self):
        """Test Semgrep execution or graceful not_installed handling."""
        res = run_semgrep_scan(self.target_dir, self.output_dir)
        self.assertEqual(res["scanner"], "semgrep")
        self.assertIn(res["status"], ["success", "failed", "not_installed"])
        self.assertIsInstance(res["findings"], list)
        if res["status"] == "not_installed":
            self.assertIn("not installed", res["error_message"].lower())
            self.assertEqual(len(res["findings"]), 0)

    def test_gitleaks_scanner_contract(self):
        """Test Gitleaks execution or graceful not_installed handling."""
        res = run_gitleaks_scan(self.target_dir, self.output_dir)
        self.assertEqual(res["scanner"], "gitleaks")
        self.assertIn(res["status"], ["success", "failed", "not_installed"])
        self.assertIsInstance(res["findings"], list)
        if res["status"] == "not_installed":
            self.assertIn("not installed", res["error_message"].lower())
            self.assertEqual(len(res["findings"]), 0)

    def test_syft_scanner_contract(self):
        """Test Syft execution or graceful not_installed handling."""
        res = run_syft_scan(self.target_dir, self.output_dir)
        self.assertEqual(res["scanner"], "syft")
        self.assertIn(res["status"], ["success", "failed", "not_installed"])
        self.assertIsInstance(res["findings"], list)
        self.assertIn("artifact_count", res)

    def test_trivy_fs_scanner_contract(self):
        """Test Trivy FS execution or graceful not_installed handling."""
        res = run_trivy_fs_scan(self.target_dir, self.output_dir)
        self.assertEqual(res["scanner"], "trivy_fs")
        self.assertIn(res["status"], ["success", "failed", "not_installed"])
        self.assertIsInstance(res["findings"], list)

    def test_trivy_image_scanner_contract(self):
        """Test Trivy Image execution or graceful not_installed handling."""
        res = run_trivy_image_scan("python:3.9-slim", self.output_dir)
        self.assertEqual(res["scanner"], "trivy_image")
        self.assertIn(res["status"], ["success", "failed", "not_installed"])
        self.assertIsInstance(res["findings"], list)

    def test_scanner_manager_all(self):
        """Test unified ScannerManager aggregates and writes manifest."""
        manager = ScannerManager(
            target_dir=self.target_dir,
            output_dir=self.output_dir,
            docker_image="sample-test-image:latest",
        )
        manifest = manager.run_all()
        self.assertIn("scan_metadata", manifest)
        self.assertIn("scanner_statuses", manifest)
        self.assertIn("semgrep", manifest["scanner_statuses"])
        self.assertIn("gitleaks", manifest["scanner_statuses"])
        self.assertIn("syft", manifest["scanner_statuses"])
        self.assertIn("trivy_fs", manifest["scanner_statuses"])
        self.assertIn("trivy_image", manifest["scanner_statuses"])

        # Check that scan_manifest.json was created on disk
        manifest_file = os.path.join(self.output_dir, "scan_manifest.json")
        self.assertTrue(os.path.exists(manifest_file))

    def test_secret_redaction(self):
        """Verify secrets are redacted and never stored in plain text."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = _redact_secret_value(raw_secret)
        self.assertNotIn("IOSFODNN7EXAMP", redacted)
        self.assertTrue(redacted.startswith("AK"))
        self.assertTrue(redacted.endswith("LE"))
        self.assertIn("***REDACTED***", redacted)

    def test_trivy_parser_normalization(self):
        """Verify Trivy JSON parser normalizes findings according to schema."""
        sample_trivy_json = {
            "Results": [
                {
                    "Target": "sample_app/requirements.txt",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-32681",
                            "PkgName": "requests",
                            "InstalledVersion": "2.25.0",
                            "FixedVersion": "2.31.0",
                            "Severity": "HIGH",
                            "Title": "Unintended leak of Proxy-Authorization header in requests",
                            "Description": "Requests is a HTTP library. Since version 2.3.0...",
                        }
                    ],
                }
            ]
        }
        findings = _parse_trivy_results(sample_trivy_json, "trivy_fs")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["id"], "CVE-2023-32681")
        self.assertEqual(finding["scanner"], "trivy_fs")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["package"], "requests")
        self.assertEqual(finding["version"], "2.25.0")
        self.assertIn("Upgrade requests to version 2.31.0", finding["remediation"])

    def test_semgrep_severity_mapping(self):
        """Verify Semgrep severity mappings."""
        self.assertEqual(semgrep_map_severity("ERROR"), "HIGH")
        self.assertEqual(semgrep_map_severity("WARNING"), "MEDIUM")
        self.assertEqual(semgrep_map_severity("INFO"), "LOW")


if __name__ == "__main__":
    unittest.main()
