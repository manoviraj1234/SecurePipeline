"""
Unit tests for SecurePipeline API Health Endpoint.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import health_check, root


class TestHealthEndpoint(unittest.TestCase):
    def test_health_check(self):
        """Health check returns ok status and project name."""
        res = health_check()
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.project, "SecurePipeline")
        self.assertEqual(res.database, "connected")
        self.assertTrue(bool(res.timestamp))

    def test_root_endpoint(self):
        """Root endpoint returns welcome message and docs links."""
        res = root()
        self.assertIn("documentation", res)
        self.assertIn("SecurePipeline", res["message"])


if __name__ == "__main__":
    unittest.main()
