"""Malformed tool output must never become a successful clean scan."""
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from scanners.gitleaks_scanner import run_gitleaks_scan
from scanners.syft_scanner import run_syft_scan
from scanners.trivy_scanner import run_trivy_fs_scan, run_trivy_image_scan


class TestScannerFailClosed(unittest.TestCase):
    def test_corrupt_file_reports_fail(self):
        cases = (
            ("gitleaks", run_gitleaks_scan, "gitleaks.json"),
            ("trivy", run_trivy_fs_scan, "trivy_fs.json"),
            ("trivy", run_trivy_image_scan, "trivy_image.json"),
        )
        for tool, scan, filename in cases:
            with self.subTest(tool=filename), tempfile.TemporaryDirectory() as directory:
                # Write through the mocked tool so this tests current-run output.
                def run(*args, **kwargs):
                    Path(directory, filename).write_text("{broken", encoding="utf-8")
                    return CompletedProcess([], 0, "", "")
                with patch(f"scanners.{tool}_scanner.shutil.which", return_value=tool), patch(f"scanners.{tool}_scanner.subprocess.run", side_effect=run):
                    result = scan("target", directory)
                self.assertEqual(result["status"], "failed")

    def test_syft_invalid_json_fails(self):
        with tempfile.TemporaryDirectory() as directory, patch("scanners.syft_scanner.shutil.which", return_value="syft"), patch("scanners.syft_scanner.subprocess.run", return_value=CompletedProcess([], 0, "{broken", "")):
            self.assertEqual(run_syft_scan("target", directory)["status"], "failed")

    def test_stale_trivy_report_cannot_hide_missing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "trivy_fs.json").write_text('{"SchemaVersion": 2, "Results": []}', encoding="utf-8")
            with patch("scanners.trivy_scanner.shutil.which", return_value="trivy"), patch("scanners.trivy_scanner.subprocess.run", return_value=CompletedProcess([], 0, "", "")):
                self.assertEqual(run_trivy_fs_scan("target", directory)["status"], "failed")
