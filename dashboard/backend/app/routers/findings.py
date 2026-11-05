"""
Findings Router for SecurePipeline API.
Provides endpoints for querying, filtering, and searching vulnerability findings.
"""

from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..database import get_db
from .. import crud, schemas

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=schemas.FindingListResponse)
def list_findings(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    scan_id: Optional[int] = None,
    severity: Optional[str] = None,
    scanner: Optional[str] = None,
    search: Optional[str] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Retrieves paginated findings with multi-criteria filtering, priority tiers, and risk score sorting."""
    findings, total = crud.get_findings(
        db,
        skip=skip,
        limit=limit,
        scan_id=scan_id,
        severity=severity,
        scanner=scanner,
        search=search,
        priority=priority,
    )
    return schemas.FindingListResponse(
        total=total,
        page=(skip // limit) + 1,
        page_size=limit,
        findings=[schemas.FindingOut.model_validate(f) for f in findings],
    )


@router.get("/{finding_id}", response_model=schemas.FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
):
    """Retrieves a single vulnerability finding by ID."""
    finding = crud.get_finding_by_id(db, finding_id=finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID {finding_id} not found.",
        )
    return finding
