"""Push 5 demo scans to SecurePipeline API for dashboard testing."""
import requests
import uuid
from datetime import datetime, timedelta

API = "http://127.0.0.1:8000/api"

# ── Scan 1: PASS (only LOW findings) ──
scan1 = {
    "report_id": str(uuid.uuid4())[:8],
    "generated_at": (datetime.now() - timedelta(hours=5)).isoformat(),
    "metadata": {"project_name": "securepipeline", "commit_hash": "a1b2c3d", "branch": "main"},
    "security_gate": {
        "decision": "PASS",
        "total_findings": 2,
        "severity_counts": {"LOW": 2},
        "explanation": "No critical or high severity findings detected.",
    },
    "total_findings": 2,
    "severity_counts": {"LOW": 2},
    "findings": [
        {
            "id": "LOW-001",
            "scanner": "semgrep",
            "severity": "LOW",
            "title": "Unused variable detected",
            "description": "Variable x is declared but never used in utils.py",
            "file": "src/utils.py",
            "line": 15,
        },
        {
            "id": "LOW-002",
            "scanner": "semgrep",
            "severity": "LOW",
            "title": "Missing docstring",
            "description": "Function process_data lacks a docstring",
            "file": "src/handlers.py",
            "line": 42,
        },
    ],
}

# ── Scan 2: BLOCK (CRITICAL + HIGH findings) ──
scan2 = {
    "report_id": str(uuid.uuid4())[:8],
    "generated_at": (datetime.now() - timedelta(hours=4)).isoformat(),
    "metadata": {"project_name": "securepipeline", "commit_hash": "e5f6g7h", "branch": "feature/auth"},
    "security_gate": {
        "decision": "BLOCK",
        "total_findings": 5,
        "severity_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
        "blocking_severities": ["CRITICAL", "HIGH"],
        "explanation": "Critical SQL injection and high-severity secrets detected.",
    },
    "total_findings": 5,
    "severity_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
    "findings": [
        {
            "id": "CRIT-001",
            "scanner": "semgrep",
            "severity": "CRITICAL",
            "title": "SQL Injection in login handler",
            "description": (
                "User input is directly concatenated into SQL query without parameterization "
                "in auth.py line 42: query = 'SELECT * FROM users WHERE id = ' + user_id"
            ),
            "file": "src/auth.py",
            "line": 42,
            "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        },
        {
            "id": "HIGH-001",
            "scanner": "gitleaks",
            "severity": "HIGH",
            "title": "AWS Secret Access Key exposed",
            "description": "AWS Secret Access Key found hardcoded in configuration file",
            "file": "config/settings.py",
            "line": 18,
            "remediation": "Move secret to environment variable or AWS Secrets Manager",
        },
        {
            "id": "HIGH-002",
            "scanner": "trivy",
            "severity": "HIGH",
            "title": "CVE-2024-29042 in express@4.17.1",
            "description": "Path traversal vulnerability in Express.js allows attackers to access files outside the intended directory",
            "package": "express",
            "installed_version": "4.17.1",
            "fixed_version": "4.19.2",
            "remediation": "Upgrade express to >= 4.19.2",
        },
        {
            "id": "MED-001",
            "scanner": "semgrep",
            "severity": "MEDIUM",
            "title": "Insecure cookie configuration",
            "description": "Session cookie is set without HttpOnly and Secure flags",
            "file": "src/middleware.py",
            "line": 33,
            "remediation": "Set httponly=True and secure=True on session cookies",
        },
        {
            "id": "LOW-003",
            "scanner": "semgrep",
            "severity": "LOW",
            "title": "Console.log in production code",
            "description": "Debug logging statement found in production code",
            "file": "src/app.js",
            "line": 99,
        },
    ],
}

# ── Scan 3: PASS (fixed critical, only MEDIUM + LOW remain) ──
scan3 = {
    "report_id": str(uuid.uuid4())[:8],
    "generated_at": (datetime.now() - timedelta(hours=3)).isoformat(),
    "metadata": {"project_name": "securepipeline", "commit_hash": "j8k9l0m", "branch": "feature/auth"},
    "security_gate": {
        "decision": "PASS",
        "total_findings": 3,
        "severity_counts": {"MEDIUM": 2, "LOW": 1},
        "explanation": "All critical and high severity findings have been resolved.",
    },
    "total_findings": 3,
    "severity_counts": {"MEDIUM": 2, "LOW": 1},
    "findings": [
        {
            "id": "MED-001",
            "scanner": "semgrep",
            "severity": "MEDIUM",
            "title": "Insecure cookie configuration",
            "description": "Session cookie is set without HttpOnly and Secure flags",
            "file": "src/middleware.py",
            "line": 33,
            "remediation": "Set httponly=True and secure=True on session cookies",
        },
        {
            "id": "MED-002",
            "scanner": "trivy",
            "severity": "MEDIUM",
            "title": "CVE-2024-28849 in follow-redirects@1.15.4",
            "description": "Proxy-Authorization header leak in follow-redirects package",
            "package": "follow-redirects",
            "installed_version": "1.15.4",
            "fixed_version": "1.15.6",
            "remediation": "Upgrade follow-redirects to >= 1.15.6",
        },
        {
            "id": "LOW-003",
            "scanner": "semgrep",
            "severity": "LOW",
            "title": "Console.log in production code",
            "description": "Debug logging statement found in production code",
            "file": "src/app.js",
            "line": 99,
        },
    ],
}

# ── Scan 4: BLOCK (new HIGH vuln introduced) ──
scan4 = {
    "report_id": str(uuid.uuid4())[:8],
    "generated_at": (datetime.now() - timedelta(hours=1)).isoformat(),
    "metadata": {"project_name": "securepipeline", "commit_hash": "n1o2p3q", "branch": "feature/payments"},
    "security_gate": {
        "decision": "BLOCK",
        "total_findings": 4,
        "severity_counts": {"HIGH": 1, "MEDIUM": 2, "LOW": 1},
        "blocking_severities": ["HIGH"],
        "explanation": "High severity XSS vulnerability detected in payment form.",
    },
    "total_findings": 4,
    "severity_counts": {"HIGH": 1, "MEDIUM": 2, "LOW": 1},
    "findings": [
        {
            "id": "HIGH-003",
            "scanner": "semgrep",
            "severity": "HIGH",
            "title": "Reflected XSS in payment form",
            "description": (
                "User-supplied input is rendered directly into HTML without escaping "
                "in payment template, allowing script injection"
            ),
            "file": "templates/payment.html",
            "line": 67,
            "remediation": "Use template auto-escaping or sanitize user input with DOMPurify",
        },
        {
            "id": "MED-001",
            "scanner": "semgrep",
            "severity": "MEDIUM",
            "title": "Insecure cookie configuration",
            "description": "Session cookie is set without HttpOnly and Secure flags",
            "file": "src/middleware.py",
            "line": 33,
        },
        {
            "id": "MED-003",
            "scanner": "semgrep",
            "severity": "MEDIUM",
            "title": "Missing CSRF protection",
            "description": "POST endpoint /api/transfer lacks CSRF token validation",
            "file": "src/routes/transfer.py",
            "line": 12,
            "remediation": "Add CSRF middleware or validate CSRF tokens on state-changing endpoints",
        },
        {
            "id": "LOW-004",
            "scanner": "semgrep",
            "severity": "LOW",
            "title": "Deprecated API usage",
            "description": "Using deprecated crypto.createCipher instead of crypto.createCipheriv",
            "file": "src/crypto.js",
            "line": 8,
        },
    ],
}

# ── Scan 5: PASS (all clean, just 1 LOW) ──
scan5 = {
    "report_id": str(uuid.uuid4())[:8],
    "generated_at": datetime.now().isoformat(),
    "metadata": {"project_name": "securepipeline", "commit_hash": "r4s5t6u", "branch": "main"},
    "security_gate": {
        "decision": "PASS",
        "total_findings": 1,
        "severity_counts": {"LOW": 1},
        "explanation": "Only informational findings remain. Deployment approved.",
    },
    "total_findings": 1,
    "severity_counts": {"LOW": 1},
    "findings": [
        {
            "id": "LOW-005",
            "scanner": "semgrep",
            "severity": "LOW",
            "title": "TODO comment in code",
            "description": "TODO comment found: refactor database connection pooling",
            "file": "src/db.py",
            "line": 5,
        },
    ],
}

# ── Push all scans ──
all_scans = [
    ("Scan 1 (PASS  - 2 LOW)", scan1),
    ("Scan 2 (BLOCK - 1 CRIT + 2 HIGH + 1 MED + 1 LOW)", scan2),
    ("Scan 3 (PASS  - 2 MED + 1 LOW, fixed critical/high)", scan3),
    ("Scan 4 (BLOCK - 1 HIGH + 2 MED + 1 LOW, new XSS)", scan4),
    ("Scan 5 (PASS  - 1 LOW, all clean)", scan5),
]

print("=" * 60)
print("  Pushing 5 demo scans to SecurePipeline dashboard...")
print("=" * 60)

for label, scan in all_scans:
    r = requests.post(f"{API}/scans/ingest", json=scan)
    status = "OK" if r.status_code == 201 else f"FAIL ({r.status_code}: {r.text[:100]})"
    print(f"  {label}: {status}")

print()
print("Done! Refresh your dashboard at http://localhost:5173")
print()
print("Your dashboard should now show:")
print("  3 x PASS  scans (green)")
print("  2 x BLOCK scans (red)")
print("  Regression trend arrows between scans")
print("  Risk scores and priority badges on findings")
