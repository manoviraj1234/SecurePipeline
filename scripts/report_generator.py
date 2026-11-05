"""
Comprehensive Security Report Generator for SecurePipeline.
Generates:
  1. reports/security_report.json
  2. reports/security_report.html
Produces professional HTML dashboards with severity badges, SBOM summaries,
and transparent security score auditing.
"""

import argparse
import html
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [report_generator]: %(message)s",
)
logger = logging.getLogger("securepipeline.report_generator")


def generate_html_content(report: Dict[str, Any]) -> str:
    """Renders a self-contained, responsive modern HTML security report."""
    meta = report.get("metadata", {})
    gate = report.get("security_gate", {})
    decision = gate.get("decision", "UNKNOWN")
    score_details = report.get("security_score", {})
    score_val = score_details.get("score")
    score_str = str(score_val) if score_val is not None else "N/A"
    
    counts = report.get("severity_counts", {})
    findings = report.get("findings", [])
    scanners = report.get("scanner_statuses", {})
    sbom = report.get("sbom", {})
    sbom_pkgs = sbom.get("packages", [])

    # Color themes for gate decision
    if decision == "PASS":
        decision_bg = "#065f46"
        decision_border = "#10b981"
        decision_text = "PASS – DEPLOYMENT APPROVED"
    elif decision == "BLOCK":
        decision_bg = "#7f1d1d"
        decision_border = "#ef4444"
        decision_text = "BLOCK – CRITICAL/HIGH VULNERABILITIES DETECTED"
    else:
        decision_bg = "#78350f"
        decision_border = "#f59e0b"
        decision_text = "INCOMPLETE – SECURITY SCANS INCOMPLETE OR FAILED (DEPLOYMENT BLOCKED)"

    # HTML table rows for scanners
    scanner_rows = []
    for sc_name, sc_info in scanners.items():
        st = sc_info.get("status", "unknown").upper()
        if st == "SUCCESS":
            st_badge = '<span style="background:#065f46;color:#34d399;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:600;">SUCCESS</span>'
        elif st == "SKIPPED":
            st_badge = '<span style="background:#374151;color:#9ca3af;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:600;">SKIPPED</span>'
        else:
            st_badge = f'<span style="background:#7f1d1d;color:#f87171;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:600;">{html.escape(st)}</span>'
        
        err = sc_info.get("error_message") or "-"
        scanner_rows.append(f"""
        <tr style="border-bottom:1px solid #1f2937;">
          <td style="padding:10px;font-weight:600;color:#f3f4f6;">{html.escape(sc_name)}</td>
          <td style="padding:10px;">{st_badge}</td>
          <td style="padding:10px;color:#9ca3af;font-size:13px;">{html.escape(err)}</td>
        </tr>
        """)

    # HTML table rows for findings
    finding_rows = []
    sev_colors = {
        "CRITICAL": ("#7f1d1d", "#f87171"),
        "HIGH": ("#7c2d12", "#fb923c"),
        "MEDIUM": ("#713f12", "#fde047"),
        "LOW": ("#065f46", "#34d399"),
        "INFO": ("#1e3a8a", "#60a5fa"),
    }
    
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        bg, text_color = sev_colors.get(sev, ("#374151", "#d1d5db"))
        sev_badge = f'<span style="background:{bg};color:{text_color};padding:4px 8px;border-radius:4px;font-size:12px;font-weight:700;">{sev}</span>'
        
        f_id = html.escape(str(f.get("id") or "UNKNOWN"))
        f_scanner = html.escape(str(f.get("scanner") or ""))
        loc = f.get("file") or f.get("package") or "codebase"
        if f.get("line"):
            loc += f":{f.get('line')}"
        loc = html.escape(str(loc))
        
        desc = html.escape(str(f.get("description") or ""))
        rem = html.escape(str(f.get("remediation") or "N/A"))
        
        finding_rows.append(f"""
        <tr style="border-bottom:1px solid #1f2937;">
          <td style="padding:10px;">{sev_badge}</td>
          <td style="padding:10px;font-family:monospace;font-weight:600;color:#e5e7eb;">{f_id}</td>
          <td style="padding:10px;color:#9ca3af;font-size:13px;">{f_scanner}</td>
          <td style="padding:10px;font-family:monospace;font-size:13px;color:#cbd5e1;">{loc}</td>
          <td style="padding:10px;color:#d1d5db;font-size:13px;">{desc}</td>
          <td style="padding:10px;color:#38bdf8;font-size:13px;">{rem}</td>
        </tr>
        """)

    findings_table_content = "".join(finding_rows)
    if not findings_table_content:
        findings_table_content = """
        <tr>
          <td colspan="6" style="padding:24px;text-align:center;color:#9ca3af;font-style:italic;">
            No vulnerability findings reported by successfully completed scanners.
          </td>
        </tr>
        """

    # SBOM rows sample (limit to top 15 in UI for readability)
    sbom_rows = []
    for p in sbom_pkgs[:15]:
        p_name = html.escape(str(p.get("name") or ""))
        p_ver = html.escape(str(p.get("version") or ""))
        p_type = html.escape(str(p.get("type") or ""))
        sbom_rows.append(f"""
        <tr style="border-bottom:1px solid #1f2937;">
          <td style="padding:8px 10px;font-weight:600;color:#f3f4f6;">{p_name}</td>
          <td style="padding:8px 10px;font-family:monospace;color:#93c5fd;">{p_ver}</td>
          <td style="padding:8px 10px;color:#9ca3af;font-size:13px;">{p_type}</td>
        </tr>
        """)
    sbom_table_content = "".join(sbom_rows)
    if not sbom_table_content:
        sbom_table_content = """
        <tr>
          <td colspan="3" style="padding:16px;text-align:center;color:#9ca3af;font-style:italic;">
            No SBOM packages registered.
          </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecurePipeline - CI/CD Security Report</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 24px;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #1e293b;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }}
    .card-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background-color: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }}
    .card-title {{
      font-size: 12px;
      color: #94a3b8;
      text-transform: uppercase;
      font-weight: 600;
      margin-bottom: 8px;
    }}
    .card-value {{
      font-size: 28px;
      font-weight: 700;
    }}
    .section-title {{
      font-size: 18px;
      font-weight: 700;
      color: #f1f5f9;
      margin-top: 32px;
      margin-bottom: 12px;
      border-left: 4px solid #38bdf8;
      padding-left: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background-color: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 24px;
    }}
    th {{
      background-color: #0f172a;
      color: #94a3b8;
      text-align: left;
      font-size: 13px;
      padding: 12px 10px;
      text-transform: uppercase;
      border-bottom: 1px solid #334155;
    }}
    .banner {{
      padding: 18px 24px;
      border-radius: 8px;
      border: 2px solid {decision_border};
      background-color: {decision_bg};
      color: #ffffff;
      font-weight: 700;
      font-size: 18px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .doc-box {{
      background-color: #1e293b;
      border-left: 4px solid #38bdf8;
      padding: 14px 18px;
      font-size: 13px;
      color: #cbd5e1;
      border-radius: 0 6px 6px 0;
      margin-bottom: 24px;
      line-height: 1.5;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin:0;font-size:26px;color:#38bdf8;">SecurePipeline</h1>
        <div style="color:#94a3b8;font-size:14px;margin-top:4px;">Automated CI/CD Vulnerability Detection &amp; Security Gate</div>
      </div>
      <div style="text-align:right;color:#94a3b8;font-size:13px;">
        Scan Time: <span style="color:#f8fafc;font-weight:600;">{html.escape(report.get("generated_at", ""))}</span><br>
        Target: <span style="font-family:monospace;color:#cbd5e1;">{html.escape(str(meta.get("target_directory", "Workspace")))}</span>
      </div>
    </div>

    <!-- Security Gate Banner -->
    <div class="banner">
      <div>{decision_text}</div>
      <div style="font-size:14px;font-weight:400;opacity:0.9;">
        Policy: Block on Critical/High
      </div>
    </div>

    <!-- KPI Metric Cards -->
    <div class="card-grid">
      <div class="card">
        <div class="card-title">Security Score</div>
        <div class="card-value" style="color:#38bdf8;">{score_str}</div>
      </div>
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-value" style="color:#f8fafc;">{report.get("total_findings", 0)}</div>
      </div>
      <div class="card">
        <div class="card-title">Critical</div>
        <div class="card-value" style="color:#ef4444;">{counts.get("CRITICAL", 0)}</div>
      </div>
      <div class="card">
        <div class="card-title">High</div>
        <div class="card-value" style="color:#f97316;">{counts.get("HIGH", 0)}</div>
      </div>
      <div class="card">
        <div class="card-title">Medium</div>
        <div class="card-value" style="color:#eab308;">{counts.get("MEDIUM", 0)}</div>
      </div>
      <div class="card">
        <div class="card-title">Low</div>
        <div class="card-value" style="color:#10b981;">{counts.get("LOW", 0)}</div>
      </div>
      <div class="card">
        <div class="card-title">SBOM Packages</div>
        <div class="card-value" style="color:#60a5fa;">{sbom.get("total_packages", 0)}</div>
      </div>
    </div>

    <!-- Security Gate Explanation -->
    <div class="doc-box">
      <strong>Gate Policy Decision:</strong> {html.escape(gate.get("explanation", ""))}<br>
      <strong>Score Formula &amp; Auditability:</strong> {html.escape(score_details.get("explanation", ""))}
    </div>

    <!-- Scanner Execution Status Section -->
    <div class="section-title">Security Scanner Execution Health</div>
    <table>
      <thead>
        <tr>
          <th>Scanner Tool</th>
          <th>Execution Status</th>
          <th>Diagnostics / Errors</th>
        </tr>
      </thead>
      <tbody>
        {"".join(scanner_rows)}
      </tbody>
    </table>

    <!-- Vulnerabilities Table -->
    <div class="section-title">Vulnerability Findings &amp; Remediation ({len(findings)})</div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Finding ID</th>
          <th>Scanner</th>
          <th>Location / Package</th>
          <th>Description</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {findings_table_content}
      </tbody>
    </table>

    <!-- SBOM Summary Section -->
    <div class="section-title">Software Bill of Materials (SBOM) Summary ({sbom.get("total_packages", 0)} Total Packages)</div>
    <table>
      <thead>
        <tr>
          <th>Package Name</th>
          <th>Version</th>
          <th>Type</th>
        </tr>
      </thead>
      <tbody>
        {sbom_table_content}
      </tbody>
    </table>

    <div style="text-align:center;color:#64748b;font-size:12px;margin-top:40px;border-top:1px solid #1e293b;padding-top:16px;">
      SecurePipeline DevSecOps System • Automated CI/CD Vulnerability Detection Report
    </div>
  </div>
</body>
</html>
"""


def generate_reports(
    aggregated_path: str = "reports/aggregated_findings.json",
    gate_path: str = "reports/security_gate.json",
    output_dir: str = "reports",
) -> Dict[str, Any]:
    """
    Generates both security_report.json and security_report.html.
    """
    os.makedirs(output_dir, exist_ok=True)
    json_output_path = os.path.join(output_dir, "security_report.json")
    html_output_path = os.path.join(output_dir, "security_report.html")

    aggregated_data: Dict[str, Any] = {}
    if os.path.exists(aggregated_path):
        try:
            with open(aggregated_path, "r", encoding="utf-8") as f:
                aggregated_data = json.load(f)
        except Exception as exc:
            logger.error("Could not parse aggregated findings from %s: %s", aggregated_path, exc)

    gate_data: Dict[str, Any] = {}
    if os.path.exists(gate_path):
        try:
            with open(gate_path, "r", encoding="utf-8") as f:
                gate_data = json.load(f)
        except Exception as exc:
            logger.error("Could not parse security gate decision from %s: %s", gate_path, exc)

    # Compile consolidated report object
    report = {
        "report_id": f"sec-rep-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": aggregated_data.get("metadata", {}),
        "security_gate": gate_data,
        "security_score": gate_data.get("score_details", {}),
        "scanner_statuses": aggregated_data.get("scanner_statuses", {}),
        "total_findings": aggregated_data.get("total_findings", 0),
        "severity_counts": aggregated_data.get("severity_counts", {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }),
        "findings": aggregated_data.get("findings", []),
        "sbom": aggregated_data.get("sbom", {"total_packages": 0, "packages": []}),
    }

    # Write JSON report
    with open(json_output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info("Generated JSON report: %s", json_output_path)

    # Write HTML report
    html_content = generate_html_content(report)
    with open(html_output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info("Generated HTML report: %s", html_output_path)

    return report


def main():
    parser = argparse.ArgumentParser(description="SecurePipeline Security Report Generator")
    parser.add_argument("--aggregated", default="reports/aggregated_findings.json", help="Path to aggregated findings JSON")
    parser.add_argument("--gate", default="reports/security_gate.json", help="Path to security gate JSON")
    parser.add_argument("--output-dir", default="reports", help="Directory to write security_report.json and security_report.html")

    args = parser.parse_args()
    res = generate_reports(
        aggregated_path=args.aggregated,
        gate_path=args.gate,
        output_dir=args.output_dir,
    )
    print(f"Reports successfully generated in: {args.output_dir}")


if __name__ == "__main__":
    main()
