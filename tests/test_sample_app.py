"""Regression coverage for the deployable sample application's attack surface."""
import unittest

from sample_app.app import app


class TestHardenedSampleApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_supported_diagnostics(self):
        for command in ("status", "version", "date"):
            with self.subTest(command=command):
                result = self.client.get("/execute", query_string={"cmd": command})
                self.assertEqual(result.status_code, 200)
                self.assertTrue(result.json["output"])

    def test_shell_payload_rejected(self):
        result = self.client.get("/execute", query_string={"cmd": "version; whoami"})
        self.assertEqual(result.status_code, 400)

    def test_json_values_supported(self):
        result = self.client.get("/eval", query_string={"expr": '{"total": 42}'})
        self.assertEqual(result.json, {"result": {"total": 42}})

    def test_python_code_rejected(self):
        result = self.client.get("/eval", query_string={"expr": "__import__('os').getcwd()"})
        self.assertEqual(result.status_code, 400)

    def test_oversized_value_rejected(self):
        result = self.client.get("/eval", query_string={"expr": '"' + 'x' * 4096 + '"'})
        self.assertEqual(result.status_code, 400)

    def test_deeply_nested_value_rejected(self):
        result = self.client.get("/eval", query_string={"expr": '[' * 1500 + '0' + ']' * 1500})
        self.assertEqual(result.status_code, 400)
