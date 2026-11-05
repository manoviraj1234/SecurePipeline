"""
Unit tests for Scan Ingestion, Querying, and Transaction Integrity.
Uses an isolated temporary SQLite database for each test.
"""

import os
import sys
import tempfile
import unittest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base
from app.routers.scans import list_scans, get_scan, ingest_scan_report, ingest_scan_report_from_file
from app.schemas import SecurityReportIngest, FindingIngest, SecurityGateIngest


class TestScansAPI(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.test_engine = create_engine(
            f"sqlite:///{self.temp_db_path}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=self.test_engine)
        self.TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.test_engine)
        self.db = self.TestSessionLocal()

    def tearDown(self):
        self.db.close()
        self.test_engine.dispose()
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def _sample_report(self, report_id="rep-001", decision="PASS", score=100, findings=None):
        findings_models = [FindingIngest(**f) for f in (findings or [])]
        gate_model = SecurityGateIngest(
            decision=decision,
            blocking_severities=["CRITICAL", "HIGH"],
            total_findings=len(findings_models),
            severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            security_score=score,
            explanation=f"Gate evaluated as {decision}",
        )
        return SecurityReportIngest(
            report_id=report_id,
            generated_at="2026-11-03T12:00:00Z",
            metadata={"project_name": "SecurePipeline", "target_directory": "/app"},
            security_gate=gate_model,
            security_score={"score": score, "status": "VERIFIED"},
            scanner_statuses={
                "semgrep": {"status": "success", "findings_count": 0},
                "gitleaks": {"status": "success", "findings_count": 0},
                "syft": {"status": "success", "artifact_count": 10},
                "trivy_fs": {"status": "success", "findings_count": 0},
            },
            total_findings=len(findings_models),
            findings=findings_models,
            sbom={"total_packages": 10, "packages": []},
        )

    def test_ingest_pass_scan(self):
        """Valid report with PASS decision must be ingested successfully."""
        report = self._sample_report(report_id="rep-pass-1", decision="PASS", score=100)
        scan = ingest_scan_report(report=report, authorized=True, db=self.db)
        self.assertEqual(scan.report_id, "rep-pass-1")
        self.assertEqual(scan.gate_decision, "PASS")
        self.assertEqual(scan.security_score, 100)
        self.assertEqual(scan.total_findings, 0)

    def test_ingest_block_scan(self):
        """Report with BLOCK decision must preserve BLOCK status and findings."""
        finding = {
            "id": "CVE-2023-32681",
            "scanner": "trivy_fs",
            "severity": "HIGH",
            "title": "Proxy leak",
            "description": "Vulnerable requests version",
            "file": "requirements.txt",
            "package": "requests",
            "installed_version": "2.25.0",
            "fixed_version": "2.31.0",
            "remediation": "Upgrade to 2.31.0",
            "fingerprint": "fp-12345",
        }
        report = self._sample_report(report_id="rep-block-1", decision="BLOCK", score=85, findings=[finding])
        scan = ingest_scan_report(report=report, authorized=True, db=self.db)
        self.assertEqual(scan.gate_decision, "BLOCK")
        self.assertEqual(scan.total_findings, 1)
        self.assertEqual(len(scan.findings), 1)
        self.assertEqual(scan.findings[0].finding_id, "CVE-2023-32681")

    def test_ingest_incomplete_scan(self):
        """Report with INCOMPLETE decision must retain INCOMPLETE status in database."""
        report = self._sample_report(report_id="rep-incomp-1", decision="INCOMPLETE", score=None)
        scan = ingest_scan_report(report=report, authorized=True, db=self.db)
        self.assertEqual(scan.gate_decision, "INCOMPLETE")
        self.assertIsNone(scan.security_score)

    def test_reject_duplicate_ingestion(self):
        """Duplicate report ID must be rejected with HTTP 409 Conflict."""
        report = self._sample_report(report_id="rep-dup-1")
        ingest_scan_report(report=report, authorized=True, db=self.db)

        with self.assertRaises(HTTPException) as ctx:
            ingest_scan_report(report=report, authorized=True, db=self.db)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("already been ingested", ctx.exception.detail)

    def test_list_scans_and_filtering(self):
        """Listing scans supports pagination and gate_decision filtering."""
        ingest_scan_report(report=self._sample_report("scan-a", "PASS"), authorized=True, db=self.db)
        ingest_scan_report(report=self._sample_report("scan-b", "BLOCK"), authorized=True, db=self.db)
        ingest_scan_report(report=self._sample_report("scan-c", "INCOMPLETE"), authorized=True, db=self.db)

        res_all = list_scans(skip=0, limit=10, gate_decision=None, db=self.db)
        self.assertEqual(res_all.total, 3)

        res_pass = list_scans(skip=0, limit=10, gate_decision="PASS", db=self.db)
        self.assertEqual(res_pass.total, 1)
        self.assertEqual(res_pass.scans[0].report_id, "scan-a")

    def test_get_scan_by_id_and_not_found(self):
        """Retrieves scan details by ID, raises 404 for invalid ID."""
        scan = ingest_scan_report(report=self._sample_report("scan-find-1"), authorized=True, db=self.db)
        found = get_scan(scan_id=scan.id, db=self.db)
        self.assertEqual(found.id, scan.id)

        with self.assertRaises(HTTPException) as ctx:
            get_scan(scan_id=99999, db=self.db)
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
