"""
Code Analysis Engine for SecurePipeline.

A comprehensive Python-based static analysis engine that uses regex pattern
matching to detect common security vulnerabilities in Python source code.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any


VULNERABILITY_PATTERNS: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # SEC-001  Command Injection via shell=True
    # -------------------------------------------------------------------------
    {
        "id": "SEC-001",
        "name": "Command Injection via shell=True",
        "pattern": re.compile(
            r"subprocess\.\w+\(.*shell\s*=\s*True", re.IGNORECASE
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "explanation": (
            "Using subprocess with shell=True passes the command through the "
            "system shell, allowing an attacker to inject arbitrary shell "
            "commands via unsanitized input. This can lead to full system "
            "compromise."
        ),
        "suggested_fix": (
            "• Pass command arguments as a list instead of a single string.\n"
            "• Set shell=False (the default) and avoid user input in commands.\n"
            "• Use shlex.quote() if shell interpolation is unavoidable."
        ),
        "improved_code": (
            "import subprocess\n"
            "# Safe: pass arguments as a list with shell=False (default)\n"
            "result = subprocess.run(\n"
            "    ['ls', '-la', sanitized_path],\n"
            "    capture_output=True, text=True, check=True\n"
            ")"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-002  Command Injection via os.system / os.popen
    # -------------------------------------------------------------------------
    {
        "id": "SEC-002",
        "name": "Command Injection via os.system/os.popen",
        "pattern": re.compile(
            r"os\.(system|popen)\s*\(", re.IGNORECASE
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "explanation": (
            "os.system() and os.popen() execute commands through the system "
            "shell. Any user-controlled data embedded in the command string "
            "can be used to execute arbitrary commands."
        ),
        "suggested_fix": (
            "• Replace os.system/os.popen with subprocess.run() using a list.\n"
            "• Never concatenate user input into command strings.\n"
            "• Validate and sanitize all external inputs."
        ),
        "improved_code": (
            "import subprocess\n"
            "# Safe: use subprocess with a list of arguments\n"
            "result = subprocess.run(\n"
            "    ['ping', '-c', '4', validated_host],\n"
            "    capture_output=True, text=True, check=True\n"
            ")"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-003  Code Injection via eval/exec
    # -------------------------------------------------------------------------
    {
        "id": "SEC-003",
        "name": "Code Injection via eval/exec",
        "pattern": re.compile(
            r"\b(eval|exec)\s*\(", re.IGNORECASE
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "owasp": "A03:2021 Injection",
        "explanation": (
            "eval() and exec() execute arbitrary Python code. If any part of "
            "the input is user-controlled, an attacker can run malicious code "
            "with the privileges of the application."
        ),
        "suggested_fix": (
            "• Use ast.literal_eval() for safe evaluation of literals.\n"
            "• Replace dynamic code execution with explicit logic or lookup tables.\n"
            "• Never pass untrusted input to eval/exec."
        ),
        "improved_code": (
            "import ast\n"
            "# Safe: use ast.literal_eval for parsing data literals\n"
            "data = ast.literal_eval(user_input)\n"
            "# Or use a dict-based dispatch instead of eval:\n"
            "actions = {'add': add_fn, 'delete': delete_fn}\n"
            "actions[validated_action]()"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-004  SQL Injection via string formatting
    # -------------------------------------------------------------------------
    {
        "id": "SEC-004",
        "name": "SQL Injection via String Formatting",
        "pattern": re.compile(
            r"cursor\.execute\s*\(\s*f['\"]|"
            r"cursor\.execute\s*\(.*%\s|"
            r"cursor\.execute\s*\(.*\.format\s*\("
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "explanation": (
            "Building SQL queries with f-strings, %-formatting, or .format() "
            "allows attackers to manipulate the query structure through "
            "malicious input, potentially accessing or destroying data."
        ),
        "suggested_fix": (
            "• Use parameterized queries with placeholders (e.g., '?' or '%s').\n"
            "• Use an ORM such as SQLAlchemy for safe query construction.\n"
            "• Validate and sanitize all user inputs used in queries."
        ),
        "improved_code": (
            "# Safe: use parameterized queries\n"
            "cursor.execute(\n"
            "    'SELECT * FROM users WHERE username = ? AND active = ?',\n"
            "    (username, True)\n"
            ")"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-005  Hardcoded Secrets (API Keys)
    # -------------------------------------------------------------------------
    {
        "id": "SEC-005",
        "name": "Hardcoded API Key / Secret",
        "pattern": re.compile(
            r"""(?:api_key|apikey|secret_key|access_key|auth_token|token)\s*=\s*['"][A-Za-z0-9+/=_\-]{8,}['"]""",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "explanation": (
            "Hardcoding API keys, tokens, or secrets in source code exposes "
            "them to anyone with access to the repository. Leaked credentials "
            "can be used to impersonate the application or access protected resources."
        ),
        "suggested_fix": (
            "• Store secrets in environment variables or a secrets manager.\n"
            "• Use .env files excluded from version control via .gitignore.\n"
            "• Rotate any secrets that have been committed to a repository."
        ),
        "improved_code": (
            "import os\n"
            "# Safe: load secrets from environment variables\n"
            "api_key = os.environ['API_KEY']\n"
            "# Or use a library like python-dotenv:\n"
            "# from dotenv import load_dotenv\n"
            "# load_dotenv()\n"
            "# api_key = os.getenv('API_KEY')"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-006  Path Traversal
    # -------------------------------------------------------------------------
    {
        "id": "SEC-006",
        "name": "Path Traversal",
        "pattern": re.compile(
            r"""open\s*\(.*(\.\./|request\.|input\s*\()""",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "explanation": (
            "Opening files using unsanitized user input or paths containing "
            "'../' allows attackers to read or write files outside the "
            "intended directory, potentially accessing sensitive system files."
        ),
        "suggested_fix": (
            "• Resolve the canonical path with os.path.realpath() and verify "
            "it stays within the allowed directory.\n"
            "• Use pathlib and check that the resolved path starts with the "
            "base directory.\n"
            "• Never pass raw user input directly to open()."
        ),
        "improved_code": (
            "from pathlib import Path\n"
            "BASE_DIR = Path('/app/uploads').resolve()\n"
            "requested = (BASE_DIR / user_filename).resolve()\n"
            "if not requested.is_relative_to(BASE_DIR):\n"
            "    raise ValueError('Path traversal detected')\n"
            "with open(requested, 'r') as f:\n"
            "    data = f.read()"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-007  Insecure Deserialization
    # -------------------------------------------------------------------------
    {
        "id": "SEC-007",
        "name": "Insecure Deserialization",
        "pattern": re.compile(
            r"pickle\.(loads?|Unpickler)\s*\(|"
            r"yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)[^)]*\)|"
            r"yaml\.load\s*\(\s*[^,)]+\s*\)",
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "explanation": (
            "Deserializing untrusted data with pickle or yaml.load (without "
            "SafeLoader) can execute arbitrary code. An attacker can craft "
            "malicious payloads that run commands upon deserialization."
        ),
        "suggested_fix": (
            "• Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).\n"
            "• Replace pickle with JSON or another safe serialization format.\n"
            "• Never deserialize data from untrusted sources."
        ),
        "improved_code": (
            "import yaml, json\n"
            "# Safe YAML loading:\n"
            "config = yaml.safe_load(yaml_string)\n"
            "# Safe alternative to pickle:\n"
            "data = json.loads(json_string)"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-008  Weak Cryptography (MD5 / SHA1)
    # -------------------------------------------------------------------------
    {
        "id": "SEC-008",
        "name": "Weak Cryptographic Hash (MD5/SHA1)",
        "pattern": re.compile(
            r"hashlib\.(md5|sha1)\s*\(", re.IGNORECASE
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-328",
        "owasp": "A02:2021 Cryptographic Failures",
        "explanation": (
            "MD5 and SHA1 are cryptographically broken and should not be used "
            "for security purposes such as password hashing or integrity "
            "verification. Collisions can be generated practically."
        ),
        "suggested_fix": (
            "• Use SHA-256 or SHA-3 for integrity checks (hashlib.sha256).\n"
            "• Use bcrypt, scrypt, or Argon2 for password hashing.\n"
            "• Only use MD5/SHA1 for non-security checksums if required."
        ),
        "improved_code": (
            "import hashlib\n"
            "# Safe: use SHA-256 for integrity checks\n"
            "digest = hashlib.sha256(data).hexdigest()\n\n"
            "# For password hashing, use bcrypt:\n"
            "import bcrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-009  Server-Side Request Forgery (SSRF)
    # -------------------------------------------------------------------------
    {
        "id": "SEC-009",
        "name": "Potential SSRF via User-Controlled URL",
        "pattern": re.compile(
            r"requests\.(get|post|put|delete|patch|head)\s*\(\s*(?!(['\"]https?://))"
            r"[a-zA-Z_]",
        ),
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "explanation": (
            "Passing a user-controlled variable as the URL to requests.get/post "
            "can allow an attacker to force the server to make requests to "
            "internal services, cloud metadata endpoints, or other restricted resources."
        ),
        "suggested_fix": (
            "• Validate and whitelist allowed URL schemes and hostnames.\n"
            "• Block requests to internal/private IP ranges (10.x, 172.16.x, 192.168.x).\n"
            "• Use an allowlist of permitted external domains."
        ),
        "improved_code": (
            "from urllib.parse import urlparse\n"
            "ALLOWED_HOSTS = {'api.example.com', 'data.example.com'}\n\n"
            "parsed = urlparse(user_url)\n"
            "if parsed.hostname not in ALLOWED_HOSTS:\n"
            "    raise ValueError('URL host not allowed')\n"
            "response = requests.get(user_url, timeout=10)"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-010  Debug Mode in Production
    # -------------------------------------------------------------------------
    {
        "id": "SEC-010",
        "name": "Debug Mode Enabled in Production",
        "pattern": re.compile(
            r"app\.run\s*\(.*debug\s*=\s*True", re.IGNORECASE
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-215",
        "owasp": "A05:2021 Security Misconfiguration",
        "explanation": (
            "Running a Flask application with debug=True exposes the "
            "interactive debugger, which allows arbitrary code execution "
            "in the browser. It also leaks detailed tracebacks and source code."
        ),
        "suggested_fix": (
            "• Set debug=False for production deployments.\n"
            "• Use environment variables to control debug mode.\n"
            "• Use a production WSGI server like Gunicorn or uWSGI."
        ),
        "improved_code": (
            "import os\n"
            "# Safe: control debug mode via environment variable\n"
            "if __name__ == '__main__':\n"
            "    app.run(\n"
            "        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',\n"
            "        host='0.0.0.0',\n"
            "        port=int(os.getenv('PORT', 5000))\n"
            "    )"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-011  Insecure Random Number Generator
    # -------------------------------------------------------------------------
    {
        "id": "SEC-011",
        "name": "Insecure Random for Security Purposes",
        "pattern": re.compile(
            r"random\.(random|randint|choice|randrange|sample)\s*\(", re.IGNORECASE
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-330",
        "owasp": "A02:2021 Cryptographic Failures",
        "explanation": (
            "Python's random module uses a Mersenne Twister PRNG that is not "
            "cryptographically secure. Using it for tokens, passwords, or "
            "session IDs makes them predictable to attackers."
        ),
        "suggested_fix": (
            "• Use secrets.token_hex() or secrets.token_urlsafe() for tokens.\n"
            "• Use secrets.choice() for cryptographically secure random selection.\n"
            "• Reserve the random module for non-security uses like simulations."
        ),
        "improved_code": (
            "import secrets\n"
            "# Safe: cryptographically secure token generation\n"
            "session_token = secrets.token_urlsafe(32)\n"
            "api_key = secrets.token_hex(32)\n"
            "otp_code = ''.join(secrets.choice('0123456789') for _ in range(6))"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-012  Insecure TLS (verify=False)
    # -------------------------------------------------------------------------
    {
        "id": "SEC-012",
        "name": "TLS Certificate Verification Disabled",
        "pattern": re.compile(
            r"requests\.\w+\(.*verify\s*=\s*False", re.IGNORECASE
        ),
        "severity": "HIGH",
        "cwe": "CWE-295",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "explanation": (
            "Setting verify=False disables TLS certificate validation, making "
            "the connection vulnerable to man-in-the-middle attacks. An "
            "attacker on the network can intercept and modify traffic."
        ),
        "suggested_fix": (
            "• Always keep verify=True (the default) in production.\n"
            "• If using a self-signed cert, provide the CA bundle path to verify=.\n"
            "• Fix the underlying certificate issue rather than disabling checks."
        ),
        "improved_code": (
            "import requests\n"
            "# Safe: TLS verification enabled (default)\n"
            "response = requests.get('https://api.example.com/data', timeout=10)\n\n"
            "# If using a custom CA bundle:\n"
            "response = requests.get(\n"
            "    'https://internal.example.com',\n"
            "    verify='/path/to/ca-bundle.crt',\n"
            "    timeout=10\n"
            ")"
        ),
    },
    # -------------------------------------------------------------------------
    # SEC-013  Hardcoded Password
    # -------------------------------------------------------------------------
    {
        "id": "SEC-013",
        "name": "Hardcoded Password",
        "pattern": re.compile(
            r"""(?:password|passwd|pwd)\s*=\s*['"][^'"]{2,}['"]""",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "explanation": (
            "Hardcoding passwords in source code exposes them to anyone who "
            "can read the codebase. If committed to version control, passwords "
            "may persist in the repository history even after removal."
        ),
        "suggested_fix": (
            "• Store passwords in environment variables or a secrets manager.\n"
            "• Use .env files excluded from version control.\n"
            "• Rotate any passwords that have been committed to a repository."
        ),
        "improved_code": (
            "import os\n"
            "# Safe: load password from environment\n"
            "db_password = os.environ['DB_PASSWORD']\n\n"
            "# Or use a secrets manager:\n"
            "# from your_secrets_lib import get_secret\n"
            "# db_password = get_secret('db_password')"
        ),
    },
]


def analyze_code(
    code: str,
    language: str = "python",
    filename: str = "submitted_code.py",
) -> dict:
    """
    Analyze source code for security vulnerabilities using regex pattern matching.

    Args:
        code: The source code to analyze.
        language: The programming language (currently only 'python' is supported).
        filename: An optional filename for reporting purposes.

    Returns:
        A structured dict containing all findings, severity counts, and a summary.
    """
    lines = code.split("\n")
    findings: List[Dict[str, Any]] = []
    finding_counter = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for vuln_pattern in VULNERABILITY_PATTERNS:
            if vuln_pattern["pattern"].search(line):
                finding_counter += 1
                findings.append(
                    {
                        "id": f"FINDING-{finding_counter:04d}",
                        "rule_id": vuln_pattern["id"],
                        "name": vuln_pattern["name"],
                        "severity": vuln_pattern["severity"],
                        "cwe": vuln_pattern["cwe"],
                        "owasp": vuln_pattern["owasp"],
                        "line_number": line_number,
                        "vulnerable_code": stripped,
                        "explanation": vuln_pattern["explanation"],
                        "suggested_fix": vuln_pattern["suggested_fix"],
                        "improved_code": vuln_pattern["improved_code"],
                    }
                )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity_counts[finding["severity"]] += 1

    total = len(findings)
    summary = (
        f"Found {total} vulnerabilities: "
        f"{severity_counts['CRITICAL']} critical, "
        f"{severity_counts['HIGH']} high, "
        f"{severity_counts['MEDIUM']} medium, "
        f"{severity_counts['LOW']} low."
    )

    return {
        "status": "success",
        "language": language,
        "filename": filename,
        "total_vulnerabilities": total,
        "severity_counts": severity_counts,
        "findings": findings,
        "summary": summary,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
    }
