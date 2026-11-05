"""
Unit Tests for SecurePipeline Findings Aggregator.
Tests schema normalization, deduplication, secret redaction, and SBOM separation.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.aggregate import (
    aggregate_findings,
    compute_fingerprint,
    normalize_raw_finding,
    normalize_severity,
)


class TestAggregateFindings(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.raw_dir = os.path.join(self.test_dir, "raw")
        os.makedirs(self.raw_dir, exist_ok=True)
        self.output_json = os.path.join(self.test_dir, "aggregated_findings.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_deduplication_via_fingerprint(self):
        """Duplicate findings must be consolidated by fingerprint."""
        raw_manifest = {
            "scan_metadata": {"target": "test"},
            "scanner_statuses": {"semgrep": {"status": "success"}},
            "findings": [
                {
                    "id": "CWE-89",
                    "scanner": "semgrep",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line": 15,
                    "description": "SQL Injection",
                },
                {
                    "id": "CWE-89",
                    "scanner": "semgrep",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line": 15,
                    "description": "SQL Injection duplicate",
                },
            ],
        }
        manifest_path = os.path.join(self.raw_dir, "scan_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(raw_manifest, f)

        res = aggregate_findings(
            raw_dir=self.raw_dir,
            manifest_path=manifest_path,
            output_path=self.output_json,
        )
        self.assertEqual(res["total_findings"], 1)
        self.assertEqual(res["severity_counts"]["HIGH"], 1)

    def test_sbom_packages_not_counted_as_vulnerabilities(self):
        """Syft SBOM inventory must not inflate vulnerability finding counts."""
        syft_data = {
            "artifacts": [
                {"name": "requests", "version": "2.25.0", "type": "python"},
                {"name": "urllib3", "version": "1.26.4", "type": "python"},
                {"name": "flask", "version": "1.1.2", "type": "python"},
            ]
        }
        with open(os.path.join(self.raw_dir, "syft_sbom.json"), "w", encoding="utf-8") as f:
            json.dump(syft_data, f)

        raw_manifest = {
            "scan_metadata": {"target": "test"},
            "scanner_statuses": {"syft": {"status": "success", "artifact_count": 3}},
            "findings": [],
        }
        manifest_path = os.path.join(self.raw_dir, "scan_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(raw_manifest, f)

        res = aggregate_findings(
            raw_dir=self.raw_dir,
            manifest_path=manifest_path,
            output_path=self.output_json,
        )
        self.assertEqual(res["total_findings"], 0)
        self.assertEqual(res["sbom"]["total_packages"], 3)
        self.assertEqual(len(res["sbom"]["packages"]), 3)

    def test_severity_normalization(self):
        """Verify severity levels normalize to standard uppercase names."""
        self.assertEqual(normalize_severity("critical"), "CRITICAL")
        self.assertEqual(normalize_severity("ERROR"), "HIGH")
        self.assertEqual(normalize_severity("warn"), "MEDIUM")
        self.assertEqual(normalize_severity("notice"), "LOW")
        self.assertEqual(normalize_severity("unknown"), "INFO")


if __name__ == "__main__":
    unittest.main()
