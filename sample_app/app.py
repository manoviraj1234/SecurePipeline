"""Hardened demo service: fixed operations and JSON parsing only."""

import json
import platform
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def home():
    return jsonify(status="running", service="securepipeline-demo")


@app.get("/execute")
def execute_command():
    """Return an allowlisted diagnostic without starting system processes."""
    operation = request.args.get("cmd", "version")
    if operation == "version":
        output = platform.python_version()
    elif operation == "status":
        output = "running"
    elif operation == "date":
        output = datetime.now(timezone.utc).isoformat()
    else:
        return jsonify(error="Unauthorized command"), 400
    return jsonify(output=output)


@app.get("/eval")
def evaluate_expression():
    """Parse JSON values; expressions and Python code are not accepted."""
    expression = request.args.get("expr", "123")
    if len(expression) > 4096:
        return jsonify(error="Input too large"), 400
    try:
        value = json.loads(expression)
    except (ValueError, RecursionError):
        return jsonify(error="Invalid JSON value"), 400
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            return jsonify(error="JSON nesting too deep"), 400
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return jsonify(result=value)


@app.get("/ping")
def ping_service():
    return jsonify(service="securepipeline-test", target=request.args.get("host", "127.0.0.1"))
