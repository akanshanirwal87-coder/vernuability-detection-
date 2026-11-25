import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Integer,
    Float,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

from db.database import Base


def utc_now() -> datetime:
    """Returns current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


class User(Base):
    """User account entity with role-based access control."""
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="USER", nullable=False)  # USER, ADMIN
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    projects: Mapped[List["Project"]] = relationship("Project", back_populates="user", cascade="all, delete-orphan")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    """Cryptographic refresh tokens for secure JWT rotation and revocation."""
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")


class Project(Base):
    """Project entity representing target codebases owned by users."""
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: f"proj-{uuid.uuid4().hex[:8]}")
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    repository_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_user_project_name"),
        Index("ix_projects_user_created", "user_id", "created_at"),
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="projects")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    """Scan execution records with aggregated vulnerability and risk metrics."""
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    project_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    project_name: Mapped[str] = mapped_column(String(150), default="Direct Scan", nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="PENDING", nullable=False, index=True)  # PENDING, RUNNING, COMPLETED, FAILED
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    highest_severity: Mapped[str] = mapped_column(String(50), default="LOW", nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lines_analyzed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source_code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings_count_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ast_summary_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ml_analysis_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_scans_user_status", "user_id", "status"),
        Index("ix_scans_project_created", "project_id", "created_at"),
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="scans")
    project: Mapped[Optional["Project"]] = relationship("Project", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    scan_jobs: Mapped[List["ScanJob"]] = relationship("ScanJob", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """Detailed vulnerability findings mapped to CWE, severity, and remediation."""
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cwe: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.9, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vulnerable_code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_status: Mapped[str] = mapped_column(String(50), default="OPEN", nullable=False, index=True)  # OPEN, IN_REVIEW, RESOLVED, FALSE_POSITIVE
    detection_source: Mapped[str] = mapped_column(String(50), default="AST", nullable=False)
    cve: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    data_flow_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    best_practices_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class ScanJob(Base):
    """Background asynchronous scan job tracking."""
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: f"job-{uuid.uuid4().hex[:8]}")
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="QUEUED", nullable=False, index=True)  # QUEUED, PROCESSING, COMPLETED, FAILED
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="scan_jobs")
