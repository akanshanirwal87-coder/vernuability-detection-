import json
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, asc, func

from db.models import Scan, Finding, ScanJob
from db.repositories.base import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    """Repository managing Scan entities, Findings, and ScanJobs."""

    def __init__(self, db: Session):
        super().__init__(Scan, db)

    def get_scan(self, scan_id: str, user_id: Optional[str] = None) -> Optional[Scan]:
        stmt = select(Scan).where(Scan.id == scan_id)
        if user_id:
            stmt = stmt.where(Scan.user_id == user_id)
        return self.db.scalars(stmt).first()

    def list_scans(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 20,
    ) -> Tuple[List[Scan], int]:
        stmt = select(Scan)
        count_stmt = select(func.count(Scan.id))

        if user_id:
            stmt = stmt.where(Scan.user_id == user_id)
            count_stmt = count_stmt.where(Scan.user_id == user_id)

        if project_id:
            stmt = stmt.where(Scan.project_id == project_id)
            count_stmt = count_stmt.where(Scan.project_id == project_id)

        if status:
            stmt = stmt.where(Scan.status == status.upper())
            count_stmt = count_stmt.where(Scan.status == status.upper())

        stmt = stmt.order_by(desc(Scan.created_at)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        scans = list(self.db.scalars(stmt).all())
        return scans, total

    def create_scan(
        self,
        scan_id: str,
        project_name: str,
        file_name: str,
        language: str,
        source_code: Optional[str] = None,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Scan:
        scan = Scan(
            id=scan_id,
            project_name=project_name,
            file_name=file_name,
            language=language,
            source_code=source_code,
            project_id=project_id,
            user_id=user_id,
            status="PENDING",
        )
        return self.create(scan)

    def complete_scan(
        self,
        scan_id: str,
        status: str,
        duration_ms: int,
        lines_analyzed: int,
        highest_severity: str,
        risk_score: int,
        findings_count: Dict[str, Any],
        ast_summary: Optional[Dict[str, Any]] = None,
        ml_analysis: Optional[Dict[str, Any]] = None,
    ) -> Optional[Scan]:
        scan = self.get(scan_id)
        if not scan:
            return None

        scan.status = status
        scan.duration_ms = duration_ms
        scan.lines_analyzed = lines_analyzed
        scan.highest_severity = highest_severity
        scan.risk_score = risk_score
        scan.findings_count_json = json.dumps(findings_count)
        scan.ast_summary_json = json.dumps(ast_summary) if ast_summary else None
        scan.ml_analysis_json = json.dumps(ml_analysis) if ml_analysis else None
        scan.completed_at = datetime.now(timezone.utc)

        self.db.commit()
        self.db.refresh(scan)
        return scan

    def add_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> List[Finding]:
        finding_objs: List[Finding] = []
        for f in findings:
            finding = Finding(
                id=f["id"],
                scan_id=scan_id,
                title=f["title"],
                category=f["category"],
                severity=f["severity"],
                cwe=f.get("cwe"),
                owasp_category=f.get("owaspCategory"),
                file_path=f.get("file") or f.get("filePath") or "source_code",
                start_line=f.get("startLine", 1),
                end_line=f.get("endLine", 1),
                confidence=float(f.get("confidence", 0.9)),
                description=f.get("description"),
                evidence=f.get("evidence"),
                impact=f.get("impact"),
                vulnerable_code=f.get("vulnerableCode"),
                remediation_code=f.get("remediationCode"),
                remediation_explanation=f.get("remediationExplanation"),
                remediation_status=f.get("remediationStatus", "OPEN"),
                detection_source=f.get("detectionSource", "AST"),
                cve=f.get("cve"),
                data_flow_json=json.dumps(f.get("dataFlow")) if f.get("dataFlow") else None,
                best_practices_json=json.dumps(f.get("bestPractices")) if f.get("bestPractices") else None,
                references_json=json.dumps(f.get("references")) if f.get("references") else None,
            )
            self.db.add(finding)
            finding_objs.append(finding)

        self.db.commit()
        return finding_objs

    def get_findings_paginated(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        cwe: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Finding], int]:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        count_stmt = select(func.count(Finding.id)).where(Finding.scan_id == scan_id)

        if severity:
            stmt = stmt.where(Finding.severity == severity.upper())
            count_stmt = count_stmt.where(Finding.severity == severity.upper())

        if cwe:
            stmt = stmt.where(Finding.cwe == cwe.upper())
            count_stmt = count_stmt.where(Finding.cwe == cwe.upper())

        stmt = stmt.order_by(asc(Finding.start_line)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        findings = list(self.db.scalars(stmt).all())
        return findings, total

    def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        stmt = select(Finding).where(Finding.id == finding_id)
        return self.db.scalars(stmt).first()

    def update_finding_validation(
        self,
        finding_id: str,
        remediation_status: str,
        explanation: Optional[str] = None,
    ) -> Optional[Finding]:
        stmt = select(Finding).where(Finding.id == finding_id)
        finding = self.db.scalars(stmt).first()
        if not finding:
            return None

        finding.remediation_status = remediation_status
        if explanation:
            finding.remediation_explanation = explanation

        self.db.commit()
        self.db.refresh(finding)
        return finding
