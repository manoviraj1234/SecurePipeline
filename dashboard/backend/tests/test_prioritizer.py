"""
Tests for Intelligent Risk Prioritization and Security Regression Engines.
"""

import unittest
from app.prioritizer import calculate_finding_risk


class TestPrioritizationEngine(unittest.TestCase):
    def test_rce_command_injection_priority(self):
        """Command injection in exposed web controller must achieve P0 critical priority."""
        finding = {
            "id": "SEC-001",
            "severity": "CRITICAL",
            "title": "Command Injection in app.py",
            "description": "User input passed to shell=True in subprocess",
            "file": "sample_app/app.py",
            "package": "subprocess",
        }
        risk_score, priority, factors = calculate_finding_risk(finding)
        self.assertGreaterEqual(risk_score, 80)
        self.assertEqual(priority, "P0")
        self.assertTrue(any("Reachable Public Endpoint" in f for f in factors))
        self.assertTrue(any("Command Injection" in f or "Shell" in f for f in factors))

    def test_isolated_test_finding_discount(self):
        """Vulnerability in test code must receive a lower contextual risk score."""
        finding = {
            "id": "SEC-002",
            "severity": "HIGH",
            "title": "Insecure mock token",
            "description": "Hardcoded test credential",
            "file": "tests/test_mock.py",
            "package": "test",
        }
        risk_score, priority, factors = calculate_finding_risk(finding)
        self.assertTrue(any("Isolated Test Component" in f for f in factors))
        self.assertLess(risk_score, 80)

    def test_low_severity_formatting_priority(self):
        """Low severity formatting issue must be categorized as P3 low priority."""
        finding = {
            "id": "SEC-003",
            "severity": "LOW",
            "title": "Template formatting notice",
            "description": "Minor formatting issue",
            "file": "templates/index.html",
        }
        risk_score, priority, factors = calculate_finding_risk(finding)
        self.assertLess(risk_score, 35)
        self.assertEqual(priority, "P3")


if __name__ == "__main__":
    unittest.main()
