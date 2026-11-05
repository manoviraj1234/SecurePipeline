"""
Dashboard Metrics Router for SecurePipeline API.
Provides aggregated KPIs, charts data, and status summaries for the frontend dashboard.
"""

from typing import Annotated, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from .. import crud, schemas

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=schemas.DashboardSummaryOut)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Provides high-level DevSecOps KPIs, recent gate decision, and total findings."""
    data = crud.get_dashboard_summary(db)
    latest_scan_out = None
    if data["latest_scan"]:
        latest_scan_out = schemas.ScanSummaryOut.model_validate(data["latest_scan"])

    return schemas.DashboardSummaryOut(
        total_scans=data["total_scans"],
        latest_scan=latest_scan_out,
        latest_gate_decision=data["latest_gate_decision"],
        latest_security_score=data["latest_security_score"],
        total_findings=data["total_findings"],
        critical_count=data["critical_count"],
        high_count=data["high_count"],
        medium_count=data["medium_count"],
        low_count=data["low_count"],
        info_count=data["info_count"],
        clean_scans_count=data["clean_scans_count"],
        blocked_scans_count=data["blocked_scans_count"],
        incomplete_scans_count=data["incomplete_scans_count"],
    )


@router.get("/severity-distribution", response_model=schemas.SeverityDistributionOut)
def get_severity_distribution(db: Session = Depends(get_db)):
    """Returns distribution of findings across severity levels for visualization."""
    data = crud.get_severity_distribution(db)
    return schemas.SeverityDistributionOut(**data)


@router.get("/scanner-status", response_model=schemas.ScannerStatusSummaryOut)
def get_scanner_status(db: Session = Depends(get_db)):
    """Returns health and execution statuses of individual security tools from latest scan."""
    data = crud.get_scanner_statuses_summary(db)
    return schemas.ScannerStatusSummaryOut(scanners=data)


@router.get("/scan-history", response_model=List[schemas.ScanSummaryOut])
def get_scan_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    db: Session = Depends(get_db),
):
    """Returns scan history for trend lines and score charts."""
    scans = crud.get_scan_history(db, limit=limit)
    return [schemas.ScanSummaryOut.model_validate(s) for s in scans]
