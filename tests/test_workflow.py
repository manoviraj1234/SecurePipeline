"""
Unit Tests for GitHub Actions Workflow Validation.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.validate_workflow import validate_workflow_yaml


class TestWorkflowValidation(unittest.TestCase):
    def test_workflow_yaml_is_valid(self):
        """Validate .github/workflows/security.yml syntax and required gate steps."""
        workflow_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "security.yml")
        )
        self.assertTrue(validate_workflow_yaml(workflow_path))


if __name__ == "__main__":
    unittest.main()
