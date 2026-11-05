"""HTTP regression tests for untrusted query parameters and report paths."""
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.routers.scans import ingest_scan_report_from_file


class TestAPIBoundaries(unittest.TestCase):
    def test_invalid_pagination_is_rejected(self):
        client = TestClient(app)
        for endpoint in ("scans", "findings", "dashboard/scan-history"):
            for limit in (0, -1, 101):
                with self.subTest(endpoint=endpoint, limit=limit):
                    response = client.get(f"/api/{endpoint}?limit={limit}")
                    self.assertEqual(response.status_code, 422)
        for endpoint in ("scans", "findings"):
            self.assertEqual(client.get(f"/api/{endpoint}?skip=-1").status_code, 422)

    def test_report_paths_cannot_escape_reports_directory(self):
        for path in ("../requirements.txt", "reports/../../requirements.txt", str(Path(__file__).resolve())):
            with self.subTest(path=path), self.assertRaises(HTTPException) as error:
                ingest_scan_report_from_file(file_path=path, authorized=True, db=None)
            self.assertEqual(error.exception.status_code, 403)

    def test_bundled_report_path_is_allowed(self):
        with patch("app.routers.scans.crud.create_scan_from_report", side_effect=ValueError("already ingested")) as create:
            with self.assertRaises(HTTPException) as error:
                ingest_scan_report_from_file(file_path="reports/security_report.json", authorized=True, db=None)
            self.assertEqual(error.exception.status_code, 409)
            create.assert_called_once()
