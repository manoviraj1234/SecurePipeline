"""
Pydantic schemas for SecurePipeline API.
Defines request payloads, responses, and serialization models.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


# =============================================================================
# INGESTION SCHEMAS (Matches Phase 4 Report Schema)
# =============================================================================
class FindingIngest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    scanner: str
    severity: str
    title: Optional[str] = None
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = Field(default_factory=list)
    fingerprint: Optional[str] = None
    risk_score: Optional[int] = None
    priority: Optional[str] = None
    risk_factors: Optional[List[str]] = Field(default_factory=list)


class ScannerStatusItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: str
    returncode: Optional[int] = None
    raw_output_path: Optional[str] = None
    error_message: Optional[str] = None
    findings_count: Optional[int] = 0
    artifact_count: Optional[int] = 0


class SecurityGateIngest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    decision: str
    timestamp: Optional[str] = None
    blocking_severities: Optional[List[str]] = Field(default_factory=list)
    total_findings: Optional[int] = 0
    severity_counts: Optional[Dict[str, int]] = Field(default_factory=dict)
    scanner_statuses: Optional[Dict[str, ScannerStatusItem]] = Field(default_factory=dict)
    blocking_findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    warnings: Optional[List[str]] = Field(default_factory=list)
    explanation: Optional[str] = ""
    security_score: Optional[int] = None


class SecurityReportIngest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    report_id: Optional[str] = None
    generated_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    security_gate: SecurityGateIngest
    security_score: Optional[Dict[str, Any]] = Field(default_factory=dict)
    scanner_statuses: Optional[Dict[str, ScannerStatusItem]] = Field(default_factory=dict)
    total_findings: Optional[int] = 0
    severity_counts: Optional[Dict[str, int]] = Field(default_factory=dict)
    findings: Optional[List[FindingIngest]] = Field(default_factory=list)
    sbom: Optional[Dict[str, Any]] = Field(default_factory=dict)


# =============================================================================
# OUTPUT SCHEMAS
# =============================================================================
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    finding_id: str
    fingerprint: str
    scanner: str
    severity: str
    title: Optional[str] = None
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    risk_score: Optional[int] = 50
    priority: Optional[str] = "P2"
    risk_factors: Optional[List[str]] = None


class FindingListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    findings: List[FindingOut]


class ScannerExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scanner_name: str
    status: str
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    findings_count: int


class ScanSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_id: str
    project_name: str
    commit_hash: Optional[str] = None
    branch: Optional[str] = None
    target_directory: Optional[str] = None
    scan_timestamp: datetime
    gate_decision: str
    security_score: Optional[int] = None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    sbom_total_packages: int


class ScanDetailOut(ScanSummaryOut):
    scanner_status: Optional[Dict[str, Any]] = None
    findings: List[FindingOut] = Field(default_factory=list)
    scanner_executions: List[ScannerExecutionOut] = Field(default_factory=list)


class ScanListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    scans: List[ScanSummaryOut]


class DashboardSummaryOut(BaseModel):
    total_scans: int
    latest_scan: Optional[ScanSummaryOut] = None
    latest_gate_decision: Optional[str] = None
    latest_security_score: Optional[int] = None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    clean_scans_count: int
    blocked_scans_count: int
    incomplete_scans_count: int


class SeverityDistributionOut(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScannerStatusSummaryOut(BaseModel):
    scanners: Dict[str, Dict[str, Any]]


class HealthResponse(BaseModel):
    status: str
    project: str
    timestamp: str
    database: str
