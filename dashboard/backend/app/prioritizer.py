"""
Intelligent Risk-Based Vulnerability Prioritization Engine for SecurePipeline.

Calculates a contextual risk score (0-100) and priority tier (P0-P3) for every vulnerability.
Considers:
1. Base Severity / CVSS mapping
2. Reachability & Asset Exposure (public web endpoints vs test code)
3. Exploitability & Threat Impact (RCE, command injection, secret leaks vs DoS)
4. Fix Actionability (availability of patched version)
"""

from typing import Any, Dict, List, Tuple


def calculate_finding_risk(finding: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Computes (risk_score, priority, risk_factors) for a given finding dict.
    
    Returns:
        risk_score: Integer from 1 to 100.
        priority: 'P0' (Critical), 'P1' (High), 'P2' (Medium), 'P3' (Low).
        risk_factors: List of human-readable rationale explanations.
    """
    severity = str(finding.get("severity") or "MEDIUM").upper().strip()
    file_path = str(finding.get("file") or "").lower()
    title = str(finding.get("title") or "").lower()
    desc = str(finding.get("description") or "").lower()
    pkg = str(finding.get("package") or "").lower()
    fixed_ver = finding.get("fixed_version")
    finding_id = str(finding.get("id") or finding.get("finding_id") or "").lower()

    combined_text = f"{title} {desc} {finding_id}"

    # 1. Base Score from Severity
    base_scores = {
        "CRITICAL": 75,
        "HIGH": 55,
        "MEDIUM": 32,
        "LOW": 15,
        "INFO": 5,
    }
    score = base_scores.get(severity, 30)
    factors: List[str] = [f"Base severity baseline: {severity}"]

    # 2. Asset Reachability & Exposure Factor
    exposed_files = ["app.py", "main.py", "server.py", "routes", "views", "controllers", "api/"]
    test_files = ["test", "mock", "fixture", "spec", "example", "sample_test"]

    if any(ef in file_path for ef in exposed_files):
        score += 15
        factors.append("Reachable Public Endpoint: Located in core web entrypoint/controller (+15)")
    elif any(tf in file_path for tf in test_files):
        score -= 20
        factors.append("Isolated Test Component: Not executed in production runtime (-20)")
    elif "dockerfile" in file_path or "container" in file_path:
        score += 8
        factors.append("Container Infrastructure Layer: Impacts deployment host security (+8)")

    if any(web_pkg in pkg for web_pkg in ["flask", "django", "fastapi", "requests", "express", "werkzeug"]):
        score += 6
        factors.append("External Ingress Dependency: Package directly processes network requests (+6)")

    # 3. Exploit Vector & Impact Factor
    high_impact_threats = [
        ("command injection", "Arbitrary OS Command Injection Vector (+20)"),
        ("shell=true", "Shell Metacharacter Execution Flaw (+20)"),
        ("rce", "Remote Code Execution (RCE) Exploit (+20)"),
        ("sql injection", "SQL Data Exfiltration / Manipulation Vector (+18)"),
        ("secret", "Hardcoded Credential / Token Exposure (+18)"),
        ("api_key", "Hardcoded API Key Leak (+18)"),
        ("eval", "Arbitrary Code Execution via eval/exec (+18)"),
        ("deserializ", "Insecure Object Deserialization Exploit (+18)"),
    ]

    low_impact_threats = [
        ("denial of service", "Denial of Service (DoS) Vector - Non-exfiltration impact (-10)"),
        ("dos", "Denial of Service without code execution (-8)"),
        ("formatting", "Minor formatting / encoding anomaly (-10)"),
        ("cookie", "Cookie configuration hardening notice (-5)"),
    ]

    impact_applied = False
    for pattern, rationale in high_impact_threats:
        if pattern in combined_text:
            score += 20
            factors.append(rationale)
            impact_applied = True
            break

    if not impact_applied:
        for pattern, rationale in low_impact_threats:
            if pattern in combined_text:
                score -= 10
                factors.append(rationale)
                break

    # 4. Fix Actionability
    if fixed_ver:
        score += 5
        factors.append(f"Immediate Remediation Available: Official patch {fixed_ver} published (+5)")

    # Normalize between 1 and 100
    risk_score = max(1, min(100, score))

    # Priority Classification
    if risk_score >= 80:
        priority = "P0"  # Critical Blocker
    elif risk_score >= 60:
        priority = "P1"  # High Priority
    elif risk_score >= 35:
        priority = "P2"  # Medium Backlog
    else:
        priority = "P3"  # Low Audit

    return risk_score, priority, factors
