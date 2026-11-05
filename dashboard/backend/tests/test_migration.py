"""Verifies older SQLite databases gain risk-prioritization columns."""

import os
import sqlite3
import sys
import tempfile
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.crud import backfill_risk_scores
from app.database import migrate_schema
from app.models import Finding


class TestLegacySchemaMigration(unittest.TestCase):
    def setUp(self):
        self.temp_fd, self.temp_path = tempfile.mkstemp(suffix=".db")
        conn = sqlite3.connect(self.temp_path)
        conn.execute(
            """
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                finding_id VARCHAR(128) NOT NULL,
                fingerprint VARCHAR(64) NOT NULL,
                scanner VARCHAR(64) NOT NULL,
                severity VARCHAR(32) NOT NULL,
                title VARCHAR(256),
                description TEXT NOT NULL,
                file VARCHAR(256),
                line INTEGER,
                package VARCHAR(128),
                installed_version VARCHAR(64),
                fixed_version VARCHAR(64),
                remediation TEXT,
                "references" JSON
            )
            """
        )
        conn.execute(
            """
            INSERT INTO findings (
                scan_id, finding_id, fingerprint, scanner, severity, title,
                description, file, package, fixed_version
            ) VALUES (
                1, 'CVE-TEST', 'fp-1', 'trivy_fs', 'HIGH', 'Command injection',
                'Remote command injection in app.py', 'sample_app/app.py',
                'flask', '2.3.3'
            )
            """
        )
        conn.commit()
        conn.close()
        self.engine = create_engine(
            f"sqlite:///{self.temp_path}",
            connect_args={"check_same_thread": False},
        )

    def tearDown(self):
        self.engine.dispose()
        os.close(self.temp_fd)
        if os.path.exists(self.temp_path):
            os.remove(self.temp_path)

    def test_migrate_and_backfill_legacy_findings(self):
        migrate_schema(self.engine)
        Session = sessionmaker(bind=self.engine)
        db = Session()
        try:
            updated = backfill_risk_scores(db)
            self.assertEqual(updated, 1)
            finding = db.query(Finding).one()
            self.assertIsNotNone(finding.risk_score)
            self.assertIn(finding.priority, {"P0", "P1", "P2", "P3"})
            self.assertTrue(finding.risk_factors)
            self.assertEqual(backfill_risk_scores(db), 0)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
