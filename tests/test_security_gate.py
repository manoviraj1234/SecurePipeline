"""
Unit Tests for SecurePipeline Security Gate.
Tests fail-closed policy, blocking severity decisions, and scanner health tracking.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.security_gate import evaluate_security_gate, calculate_security_score


class TestSecurityGate(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.aggregated_file = os.path.join(self.test_dir, "aggregated_findings.json")
        self.gate_output = os.path.join(self.test_dir, "security_gate.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_aggregated(self, scanner_statuses, findings, severity_counts=None, metadata=None):
        if severity_counts is None:
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                sev = f.get("severity", "MEDIUM")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        payload = {
            "metadata": metadata or {},
            "scanner_statuses": scanner_statuses,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "findings": findings,
            "sbom": {"total_packages": 5, "packages": []},
        }
        with open(self.aggregated_file, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def test_all_scanners_clean_passes(self):
        """All required scanners success with zero findings must PASS (exit 0)."""
        statuses = {
            "semgrep": {"status": "success"},
            "gitleaks": {"status": "success"},
            "syft": {"status": "success"},
            "trivy_fs": {"status": "success"},
        }
        self._write_aggregated(statuses, findings=[])

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "PASS")
        self.assertEqual(code, 0)
        self.assertEqual(res["security_score"], 100)
        self.assertEqual(len(res["blocking_findings"]), 0)

    def test_critical_vulnerability_blocks(self):
        """CRITICAL vulnerability must BLOCK deployment (exit 1)."""
        statuses = {
            "semgrep": {"status": "success"},
            "gitleaks": {"status": "success"},
            "syft": {"status": "success"},
            "trivy_fs": {"status": "success"},
        }
        findings = [
            {"id": "CVE-2023-9999", "scanner": "trivy_fs", "severity": "CRITICAL", "description": "RCE in dependency"}
        ]
        self._write_aggregated(statuses, findings)

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "BLOCK")
        self.assertEqual(code, 1)
        self.assertEqual(len(res["blocking_findings"]), 1)
        self.assertEqual(res["security_score"], 75)  # 100 - 25

    def test_high_vulnerability_blocks(self):
        """HIGH severity finding (e.g. secret or high CVE) must BLOCK deployment (exit 1)."""
        statuses = {
            "semgrep": {"status": "success"},
            "gitleaks": {"status": "success"},
            "syft": {"status": "success"},
            "trivy_fs": {"status": "success"},
        }
        findings = [
            {"id": "generic-api-key", "scanner": "gitleaks", "severity": "HIGH", "description": "API Key exposed"}
        ]
        self._write_aggregated(statuses, findings)

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "BLOCK")
        self.assertEqual(code, 1)
        self.assertEqual(len(res["blocking_findings"]), 1)
        self.assertEqual(res["security_score"], 85)  # 100 - 15

    def test_medium_and_low_only_passes_with_warnings(self):
        """MEDIUM and LOW findings should not block; gate must PASS (exit 0) with warnings."""
        statuses = {
            "semgrep": {"status": "success"},
            "gitleaks": {"status": "success"},
            "syft": {"status": "success"},
            "trivy_fs": {"status": "success"},
        }
        findings = [
            {"id": "RULE-LOW-01", "scanner": "semgrep", "severity": "LOW", "description": "Minor doc comment issue"},
            {"id": "CVE-2021-1234", "scanner": "trivy_fs", "severity": "MEDIUM", "description": "Moderate issue"},
        ]
        self._write_aggregated(statuses, findings)

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "PASS")
        self.assertEqual(code, 0)
        self.assertEqual(len(res["blocking_findings"]), 0)
        self.assertEqual(len(res["warnings"]), 2)
        self.assertEqual(res["security_score"], 94)  # 100 - (5 + 1)

    def test_scanner_execution_failure_is_incomplete(self):
        """Scanner failure (e.g. exit code crash or status failed) must be INCOMPLETE (exit 2)."""
        statuses = {
            "semgrep": {"status": "failed", "error_message": "Segmentation fault"},
            "gitleaks": {"status": "success"},
            "syft": {"status": "success"},
            "trivy_fs": {"status": "success"},
        }
        self._write_aggregated(statuses, findings=[])

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "INCOMPLETE")
        self.assertEqual(code, 2)
        self.assertIsNone(res["security_score"])

    def test_missing_required_scanner_is_incomplete(self):
        """Omission of a required scanner in the manifest must result in INCOMPLETE (exit 2)."""
        # syft missing
        statuses = {
            "semgrep": {"status": "success"},
            "gitleaks": {"status": "success"},
            "trivy_fs": {"status": "success"},
        }
        self._write_aggregated(statuses, findings=[])

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "INCOMPLETE")
        self.assertEqual(code, 2)

    def test_corrupted_json_is_incomplete(self):
        """Malformed or corrupted aggregated JSON must fail-closed as INCOMPLETE (exit 2)."""
        with open(self.aggregated_file, "w", encoding="utf-8") as f:
            f.write("{ invalid-json-syntax !! ")

        decision, code, res = evaluate_security_gate(
            aggregated_path=self.aggregated_file,
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "INCOMPLETE")
        self.assertEqual(code, 2)

    def test_missing_report_file_is_incomplete(self):
        """Non-existent report file must fail-closed as INCOMPLETE (exit 2)."""
        decision, code, res = evaluate_security_gate(
            aggregated_path=os.path.join(self.test_dir, "does_not_exist.json"),
            manifest_path=os.path.join(self.test_dir, "manifest_also_not_here.json"),
            output_path=self.gate_output,
        )
        self.assertEqual(decision, "INCOMPLETE")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
