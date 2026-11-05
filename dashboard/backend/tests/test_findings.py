"""
Unit tests for Finding Query and Filtering Endpoints.
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
from app.routers.scans import ingest_scan_report
from app.routers.findings import list_findings, get_finding
from app.schemas import SecurityReportIngest, FindingIngest, SecurityGateIngest


class TestFindingsAPI(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.test_engine = create_engine(
            f"sqlite:///{self.temp_db_path}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=self.test_engine)
        self.TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.test_engine)
        self.db = self.TestSessionLocal()

        # Ingest a scan with diverse findings for testing
        report = SecurityReportIngest(
            report_id="scan-findings-test",
            security_gate=SecurityGateIngest(
                decision="BLOCK",
                total_findings=3,
                severity_counts={"CRITICAL": 1, "HIGH": 1, "LOW": 1},
            ),
            findings=[
                FindingIngest(
                    id="CVE-2023-CRIT",
                    scanner="trivy_fs",
                    severity="CRITICAL",
                    title="Remote Code Execution",
                    description="Critical vulnerability in werkzeug",
                    package="werkzeug",
                    file="requirements.txt",
                ),
                FindingIngest(
                    id="AWS-KEY-LEAK",
                    scanner="gitleaks",
                    severity="HIGH",
                    title="Hardcoded AWS Key",
                    description="AWS token found",
                    file="app.py",
                    line=10,
                ),
                FindingIngest(
                    id="SEM-001",
                    scanner="semgrep",
                    severity="LOW",
                    title="Style violation",
                    description="Minor lint issue",
                    file="app.py",
                    line=42,
                ),
            ],
        )
        ingest_scan_report(report=report, authorized=True, db=self.db)

    def tearDown(self):
        self.db.close()
        self.test_engine.dispose()
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_list_all_findings(self):
        """list_findings returns all ingested findings."""
        res = list_findings(skip=0, limit=50, db=self.db)
        self.assertEqual(res.total, 3)
        self.assertEqual(len(res.findings), 3)

    def test_filter_by_severity(self):
        """Filtering by severity returns matching items."""
        res = list_findings(skip=0, limit=50, severity="CRITICAL", db=self.db)
        self.assertEqual(res.total, 1)
        self.assertEqual(res.findings[0].finding_id, "CVE-2023-CRIT")

    def test_filter_by_scanner(self):
        """Filtering by scanner returns matching items."""
        res = list_findings(skip=0, limit=50, scanner="gitleaks", db=self.db)
        self.assertEqual(res.total, 1)
        self.assertEqual(res.findings[0].scanner, "gitleaks")

    def test_search_findings(self):
        """Searching on package name matches properly."""
        res = list_findings(skip=0, limit=50, search="werkzeug", db=self.db)
        self.assertEqual(res.total, 1)
        self.assertEqual(res.findings[0].package, "werkzeug")

    def test_get_finding_by_id(self):
        """Retrieving specific finding by ID succeeds."""
        all_findings = list_findings(skip=0, limit=50, db=self.db)
        first_id = all_findings.findings[0].id

        found = get_finding(finding_id=first_id, db=self.db)
        self.assertEqual(found.id, first_id)

    def test_get_finding_not_found(self):
        """Non-existent finding ID raises HTTP 404."""
        with self.assertRaises(HTTPException) as ctx:
            get_finding(finding_id=99999, db=self.db)
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
