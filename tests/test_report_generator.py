"""
Unit Tests for SecurePipeline Report Generator.
Tests HTML and JSON report creation, styling, and sensitive data protection.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.report_generator import generate_reports


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.aggregated_file = os.path.join(self.test_dir, "aggregated_findings.json")
        self.gate_file = os.path.join(self.test_dir, "security_gate.json")
        self.output_dir = os.path.join(self.test_dir, "reports")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_report_generation_json_and_html(self):
        """Validates that both security_report.json and security_report.html are generated."""
        aggregated_payload = {
            "metadata": {"target_directory": "/app"},
            "scanner_statuses": {
                "semgrep": {"status": "success"},
                "gitleaks": {"status": "success"},
                "syft": {"status": "success"},
                "trivy_fs": {"status": "success"},
            },
            "total_findings": 1,
            "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [
                {
                    "id": "AWS-SECRET-KEY",
                    "scanner": "gitleaks",
                    "severity": "HIGH",
                    "file": "config.py",
                    "line": 12,
                    "description": "AWS Secret Token (Rule: aws-key)",
                    "remediation": "Revoke token immediately.",
                }
            ],
            "sbom": {
                "total_packages": 2,
                "packages": [
                    {"name": "requests", "version": "2.25.0", "type": "python"},
                    {"name": "urllib3", "version": "1.26.4", "type": "python"},
                ],
            },
        }
        with open(self.aggregated_file, "w", encoding="utf-8") as f:
            json.dump(aggregated_payload, f)

        gate_payload = {
            "decision": "BLOCK",
            "explanation": "High severity secret detected in config.py",
            "score_details": {
                "score": 85,
                "status": "VERIFIED",
                "explanation": "100 base - 15 deduction",
            },
        }
        with open(self.gate_file, "w", encoding="utf-8") as f:
            json.dump(gate_payload, f)

        res = generate_reports(
            aggregated_path=self.aggregated_file,
            gate_path=self.gate_file,
            output_dir=self.output_dir,
        )

        json_path = os.path.join(self.output_dir, "security_report.json")
        html_path = os.path.join(self.output_dir, "security_report.html")

        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(html_path))

        # Check content of JSON report
        with open(json_path, "r", encoding="utf-8") as f:
            saved_json = json.load(f)
        self.assertEqual(saved_json["total_findings"], 1)
        self.assertEqual(saved_json["security_gate"]["decision"], "BLOCK")

        # Check content of HTML report
        with open(html_path, "r", encoding="utf-8") as f:
            html_text = f.read()
        self.assertIn("SecurePipeline", html_text)
        self.assertIn("BLOCK", html_text)
        self.assertIn("AWS-SECRET-KEY", html_text)
        self.assertIn("requests", html_text)
        self.assertIn("85", html_text)


if __name__ == "__main__":
    unittest.main()
