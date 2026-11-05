"""
SQLAlchemy Database Models for SecurePipeline.
Stores scans, findings, and scanner execution health.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Float,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    project_name = Column(String(128), default="SecurePipeline", index=True)
    commit_hash = Column(String(64), nullable=True, index=True)
    branch = Column(String(64), nullable=True)
    target_directory = Column(String(256), nullable=True)
    scan_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Gate policy outcome: PASS, BLOCK, or INCOMPLETE
    gate_decision = Column(String(32), index=True, nullable=False)
    security_score = Column(Integer, nullable=True)
    
    # Severity counts
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Scanner summary & SBOM
    scanner_status = Column(JSON, nullable=True)
    sbom_total_packages = Column(Integer, default=0)
    report_json = Column(JSON, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    scanner_executions = relationship("ScannerExecution", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_decision_timestamp", "gate_decision", "scan_timestamp"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    finding_id = Column(String(128), index=True, nullable=False)
    fingerprint = Column(String(64), index=True, nullable=False)
    scanner = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    title = Column(String(256), nullable=True)
    description = Column(Text, nullable=False)
    file = Column(String(256), nullable=True, index=True)
    line = Column(Integer, nullable=True)
    package = Column(String(128), nullable=True, index=True)
    installed_version = Column(String(64), nullable=True)
    fixed_version = Column(String(64), nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)

    # Intelligent Risk Prioritization
    risk_score = Column(Integer, default=50, index=True)
    priority = Column(String(16), default="P2", index=True)  # P0, P1, P2, P3
    risk_factors = Column(JSON, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_severity", "scan_id", "severity"),
        Index("idx_findings_priority", "priority"),
    )


class ScannerExecution(Base):
    __tablename__ = "scanner_executions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    scanner_name = Column(String(64), index=True, nullable=False)
    status = Column(String(32), index=True, nullable=False)  # success, failed, not_installed, skipped
    execution_time = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)

    # Relationships
    scan = relationship("Scan", back_populates="scanner_executions")
