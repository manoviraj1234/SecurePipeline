"""
Unit tests for Dashboard Aggregation and KPI Endpoints.
"""

import os
import sys
import tempfile
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base
from app.routers.scans import ingest_scan_report
from app.routers.dashboard import (
    get_dashboard_summary,
    get_severity_distribution,
    get_scanner_status,
    get_scan_history,
)
from app.schemas import SecurityReportIngest, FindingIngest, SecurityGateIngest, ScannerStatusItem


class TestDashboardAPI(unittest.TestCase):
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

    def test_empty_database_summary(self):
        """Dashboard summary must handle empty database cleanly without crashes."""
        summary = get_dashboard_summary(db=self.db)
        self.assertEqual(summary.total_scans, 0)
        self.assertIsNone(summary.latest_scan)
        self.assertEqual(summary.clean_scans_count, 0)
        self.assertEqual(summary.blocked_scans_count, 0)

    def test_populated_dashboard_metrics(self):
        """Dashboard summary correctly aggregates metrics from scans."""
        scan1 = SecurityReportIngest(
            report_id="dash-1",
            security_gate=SecurityGateIngest(
                decision="PASS",
                total_findings=0,
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                security_score=100,
            ),
            scanner_statuses={
                "semgrep": ScannerStatusItem(status="success"),
                "gitleaks": ScannerStatusItem(status="success"),
            },
        )
        scan2 = SecurityReportIngest(
            report_id="dash-2",
            security_gate=SecurityGateIngest(
                decision="BLOCK",
                total_findings=2,
                severity_counts={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                security_score=60,
            ),
            findings=[
                FindingIngest(id="V-1", scanner="trivy_fs", severity="CRITICAL", description="critical CVE"),
                FindingIngest(id="V-2", scanner="gitleaks", severity="HIGH", description="secret key"),
            ],
            scanner_statuses={
                "semgrep": ScannerStatusItem(status="success"),
                "trivy_fs": ScannerStatusItem(status="success"),
            },
        )
        ingest_scan_report(report=scan1, authorized=True, db=self.db)
        ingest_scan_report(report=scan2, authorized=True, db=self.db)

        summary = get_dashboard_summary(db=self.db)
        self.assertEqual(summary.total_scans, 2)
        self.assertEqual(summary.clean_scans_count, 1)
        self.assertEqual(summary.blocked_scans_count, 1)
        self.assertEqual(summary.latest_gate_decision, "BLOCK")
        self.assertEqual(summary.latest_security_score, 60)

    def test_severity_distribution(self):
        """get_severity_distribution returns correct severity breakdown."""
        scan = SecurityReportIngest(
            report_id="dist-test",
            security_gate=SecurityGateIngest(
                decision="BLOCK",
                severity_counts={"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 4, "INFO": 0},
            ),
        )
        ingest_scan_report(report=scan, authorized=True, db=self.db)

        dist = get_severity_distribution(db=self.db)
        self.assertEqual(dist.critical, 2)
        self.assertEqual(dist.high, 3)
        self.assertEqual(dist.medium, 1)
        self.assertEqual(dist.low, 4)

    def test_scan_history(self):
        """get_scan_history returns ordered scans limited to parameter."""
        for i in range(3):
            scan = SecurityReportIngest(
                report_id=f"hist-{i}",
                security_gate=SecurityGateIngest(decision="PASS", security_score=100),
            )
            ingest_scan_report(report=scan, authorized=True, db=self.db)

        history = get_scan_history(limit=2, db=self.db)
        self.assertEqual(len(history), 2)


if __name__ == "__main__":
    unittest.main()
