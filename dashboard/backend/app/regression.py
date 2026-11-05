"""
Security Regression Detection Engine for SecurePipeline.

Compares consecutive security scans across pipeline commits to detect:
1. New Vulnerabilities (Security Regressions introduced by new code)
2. Resolved Vulnerabilities (Patches applied and verified fixed)
3. Unchanged Vulnerabilities (Technical security debt)
4. Score Velocity (Improvement or deterioration over time)
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from . import models


def calculate_scan_regression(db: Session, current_scan_id: int) -> Dict[str, Any]:
    """
    Compares the specified scan against the immediately preceding scan in the database.
    """
    current_scan = db.query(models.Scan).filter(models.Scan.id == current_scan_id).first()
    if not current_scan:
        return {"status": "NOT_FOUND", "message": f"Scan {current_scan_id} not found."}

    # Find the previous scan
    previous_scan = (
        db.query(models.Scan)
        .filter(models.Scan.id < current_scan_id)
        .order_by(models.Scan.id.desc())
        .first()
    )

    current_findings = current_scan.findings or []
    current_fingerprints = {f.fingerprint: f for f in current_findings if f.fingerprint}

    if not previous_scan:
        return {
            "status": "INITIAL",
            "message": "Baseline scan. No previous scan exists for regression comparison.",
            "current_scan_id": current_scan_id,
            "previous_scan_id": None,
            "new_count": len(current_findings),
            "fixed_count": 0,
            "unchanged_count": 0,
            "score_delta": 0,
            "new_findings": [
                {
                    "id": f.finding_id,
                    "title": f.title or f.finding_id,
                    "severity": f.severity,
                    "file": f.file,
                    "priority": getattr(f, "priority", "P2"),
                }
                for f in current_findings[:10]
            ],
            "fixed_findings": [],
        }

    previous_findings = previous_scan.findings or []
    previous_fingerprints = {f.fingerprint: f for f in previous_findings if f.fingerprint}

    # Set calculations
    curr_fps = set(current_fingerprints.keys())
    prev_fps = set(previous_fingerprints.keys())

    new_fps = curr_fps - prev_fps
    fixed_fps = prev_fps - curr_fps
    unchanged_fps = curr_fps & prev_fps

    # Score Delta
    curr_score = current_scan.security_score if current_scan.security_score is not None else 0
    prev_score = previous_scan.security_score if previous_scan.security_score is not None else 0
    score_delta = curr_score - prev_score

    # Determine status
    if len(new_fps) > 0:
        regression_status = "REGRESSED"
    elif len(fixed_fps) > 0 and len(curr_fps) < len(prev_fps):
        regression_status = "IMPROVED"
    elif len(curr_fps) == 0:
        regression_status = "CLEAN"
    else:
        regression_status = "UNCHANGED"

    new_items = [
        {
            "id": current_fingerprints[fp].finding_id,
            "title": current_fingerprints[fp].title or current_fingerprints[fp].finding_id,
            "severity": current_fingerprints[fp].severity,
            "file": current_fingerprints[fp].file,
            "priority": getattr(current_fingerprints[fp], "priority", "P2"),
        }
        for fp in list(new_fps)[:10]
    ]

    fixed_items = [
        {
            "id": previous_fingerprints[fp].finding_id,
            "title": previous_fingerprints[fp].title or previous_fingerprints[fp].finding_id,
            "severity": previous_fingerprints[fp].severity,
            "file": previous_fingerprints[fp].file,
        }
        for fp in list(fixed_fps)[:10]
    ]

    return {
        "status": regression_status,
        "current_scan_id": current_scan_id,
        "previous_scan_id": previous_scan.id,
        "previous_commit": previous_scan.commit_hash or "prev",
        "current_commit": current_scan.commit_hash or "curr",
        "new_count": len(new_fps),
        "fixed_count": len(fixed_fps),
        "unchanged_count": len(unchanged_fps),
        "score_delta": score_delta,
        "current_score": curr_score,
        "previous_score": prev_score,
        "new_findings": new_items,
        "fixed_findings": fixed_items,
    }
