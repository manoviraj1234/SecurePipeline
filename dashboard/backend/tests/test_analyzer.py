"""
Tests for the SecurePipeline Code Analysis Engine.
"""

import unittest

from app.analyzer import analyze_code, VULNERABILITY_PATTERNS


# A deliberately vulnerable code sample covering multiple pattern categories.
VULNERABLE_CODE = """\
import subprocess
import os
import random
import hashlib
import pickle
import yaml
import requests

# SEC-001: Command Injection via shell=True
subprocess.run(f"ls {user_input}", shell=True)

# SEC-002: Command Injection via os.system
os.system("rm -rf " + user_input)

# SEC-003: Code Injection via eval
result = eval(user_input)

# SEC-004: SQL Injection via f-string
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SEC-005: Hardcoded API key
api_key = "AKIAIOSFODNN7EXAMPLE"

# SEC-006: Path traversal
data = open("../../../etc/passwd")

# SEC-007: Insecure deserialization – pickle
obj = pickle.loads(data)

# SEC-007: Insecure deserialization – yaml
config = yaml.load(raw_yaml)

# SEC-008: Weak cryptography
digest = hashlib.md5(payload).hexdigest()

# SEC-009: SSRF – user-controlled URL
response = requests.get(user_url)

# SEC-010: Debug mode in production
app.run(debug=True)

# SEC-011: Insecure random
token = random.randint(100000, 999999)

# SEC-012: Insecure TLS
resp = requests.get("https://example.com", verify=False)

# SEC-013: Hardcoded password
password = "SuperSecret123!"
"""

# Safe code that should produce zero findings.
SAFE_CODE = """\
import os
import json
import secrets
import hashlib
import subprocess

# Safe subprocess usage
result = subprocess.run(['ls', '-la'], capture_output=True, text=True)

# Safe secret loading
api_key = os.environ.get('API_KEY')

# Safe hashing
digest = hashlib.sha256(b'data').hexdigest()

# Safe token generation
token = secrets.token_urlsafe(32)

# Safe JSON parsing
data = json.loads('{"key": "value"}')
"""

REQUIRED_FINDING_FIELDS = {
    "id", "rule_id", "name", "severity", "cwe",
    "owasp", "line_number", "vulnerable_code",
    "explanation", "suggested_fix", "improved_code",
}


class TestAnalyzeCodeVulnerable(unittest.TestCase):
    """Tests using the deliberately vulnerable code sample."""

    def setUp(self):
        self.result = analyze_code(
            code=VULNERABLE_CODE,
            language="python",
            filename="vulnerable_sample.py",
        )

    def test_status_is_success(self):
        self.assertEqual(self.result["status"], "success")

    def test_language_and_filename(self):
        self.assertEqual(self.result["language"], "python")
        self.assertEqual(self.result["filename"], "vulnerable_sample.py")

    def test_total_vulnerabilities_detected(self):
        """At least the 14 distinct vulnerable lines should be detected."""
        self.assertGreaterEqual(self.result["total_vulnerabilities"], 14)

    def test_each_finding_has_required_fields(self):
        for finding in self.result["findings"]:
            for field in REQUIRED_FINDING_FIELDS:
                self.assertIn(
                    field, finding,
                    f"Finding {finding.get('id', '?')} missing field '{field}'",
                )

    def test_severity_counts_sum(self):
        counts = self.result["severity_counts"]
        total_from_counts = sum(counts.values())
        self.assertEqual(total_from_counts, self.result["total_vulnerabilities"])

    def test_severity_counts_contain_critical(self):
        self.assertGreater(self.result["severity_counts"]["CRITICAL"], 0)

    def test_severity_counts_contain_high(self):
        self.assertGreater(self.result["severity_counts"]["HIGH"], 0)

    def test_severity_counts_contain_medium(self):
        self.assertGreater(self.result["severity_counts"]["MEDIUM"], 0)

    def test_summary_present(self):
        self.assertIn("Found", self.result["summary"])
        self.assertIn("vulnerabilities", self.result["summary"])

    def test_analysis_timestamp_present(self):
        self.assertIsInstance(self.result["analysis_timestamp"], str)
        self.assertGreater(len(self.result["analysis_timestamp"]), 0)

    def test_findings_have_correct_line_numbers(self):
        for finding in self.result["findings"]:
            self.assertIsInstance(finding["line_number"], int)
            self.assertGreater(finding["line_number"], 0)


class TestAnalyzeCodeSafe(unittest.TestCase):
    """Tests using safe code – should yield zero findings."""

    def setUp(self):
        self.result = analyze_code(code=SAFE_CODE)

    def test_zero_findings(self):
        self.assertEqual(self.result["total_vulnerabilities"], 0)

    def test_empty_findings_list(self):
        self.assertEqual(len(self.result["findings"]), 0)

    def test_all_severity_counts_zero(self):
        for severity, count in self.result["severity_counts"].items():
            self.assertEqual(
                count, 0,
                f"Expected 0 {severity} findings in safe code, got {count}",
            )


class TestVulnerabilityPatterns(unittest.TestCase):
    """Tests for the patterns metadata list."""

    def test_minimum_pattern_count(self):
        self.assertGreaterEqual(len(VULNERABILITY_PATTERNS), 12)

    def test_pattern_required_keys(self):
        required_keys = {
            "id", "name", "pattern", "severity", "cwe",
            "owasp", "explanation", "suggested_fix", "improved_code",
        }
        for p in VULNERABILITY_PATTERNS:
            for key in required_keys:
                self.assertIn(
                    key, p,
                    f"Pattern {p.get('id', '?')} missing key '{key}'",
                )

    def test_pattern_ids_unique(self):
        ids = [p["id"] for p in VULNERABILITY_PATTERNS]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate pattern IDs found")

    def test_valid_severities(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for p in VULNERABILITY_PATTERNS:
            self.assertIn(
                p["severity"], valid,
                f"Pattern {p['id']} has invalid severity '{p['severity']}'",
            )


if __name__ == "__main__":
    unittest.main()
