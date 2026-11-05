"""
Sample Vulnerable Test Application for SecurePipeline Validation.
Includes intentional patterns for testing SAST, secret detection, and dependencies.
"""

import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# Intentional secret test pattern for Gitleaks detection
# Standard dummy token pattern for validation purposes
DEMO_API_KEY = "AKIAIOSFODNN7EXAMPLE"  # Standard AWS test key format


@app.route("/")
def home():
    return jsonify({"status": "running", "service": "sample-vulnerable-app"})


@app.route("/execute")
def execute_command():
    """Intentional SAST test pattern for Semgrep (Command Injection / shell=True)."""
    user_cmd = request.args.get("cmd", "echo hello")
    # Insecure use of shell=True with user-provided input
    result = subprocess.check_output(user_cmd, shell=True, text=True)
    return jsonify({"output": result})


@app.route("/eval")
def evaluate_expression():
    """Intentional SAST test pattern for Semgrep (eval)."""
    expr = request.args.get("expr", "1 + 1")
    # Insecure use of eval
    val = eval(expr)
    return jsonify({"result": val})


@app.route("/ping")
def ping_service():
    """CI/CD validation test endpoint for live pipeline trigger."""
    target = request.args.get("host", "127.0.0.1")
    return jsonify({"service": "securepipeline-test", "target": target})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

# Test pipeline run: 11/04/2026 11:39:23
