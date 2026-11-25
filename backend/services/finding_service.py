import json
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from core.exceptions import EntityNotFoundException, AuthorizationException
from db.models import Finding, Scan
from db.repositories.scan_repository import ScanRepository


class FindingService:
    """Service managing vulnerability findings retrieval, filtering, and status updates."""

    def __init__(self, db: Session):
        self.db = db
        self.repo = ScanRepository(db)

    def list_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        cwe: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        user_id: Optional[str] = None,
        is_admin: bool = False,
    ) -> Tuple[List[Dict[str, Any]], int]:
        scan = self.repo.get(scan_id)
        if not scan:
            raise EntityNotFoundException("Scan", scan_id)

        if scan.user_id and user_id and not is_admin and scan.user_id != user_id:
            raise AuthorizationException("Access denied: You cannot view findings for this scan.")

        finding_objs, total = self.repo.get_findings_paginated(
            scan_id=scan_id,
            severity=severity,
            cwe=cwe,
            skip=skip,
            limit=limit,
        )

        items = []
        for f in finding_objs:
            items.append({
                "id": f.id,
                "scanId": f.scan_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "cwe": f.cwe,
                "owaspCategory": f.owasp_category,
                "file": f.file_path,
                "startLine": f.start_line,
                "endLine": f.end_line,
                "confidence": f.confidence,
                "description": f.description,
                "evidence": f.evidence,
                "impact": f.impact,
                "vulnerableCode": f.vulnerable_code,
                "remediationCode": f.remediation_code,
                "remediationExplanation": f.remediation_explanation,
                "remediationStatus": f.remediation_status,
                "detectionSource": f.detection_source,
                "cve": f.cve,
                "dataFlow": json.loads(f.data_flow_json) if f.data_flow_json else [],
                "bestPractices": json.loads(f.best_practices_json) if f.best_practices_json else [],
                "references": json.loads(f.references_json) if f.references_json else [],
                "createdAt": f.created_at.isoformat(),
            })
        return items, total

    def update_finding(
        self,
        finding_id: str,
        status: str,
        explanation: Optional[str] = None,
        user_id: Optional[str] = None,
        is_admin: bool = False,
    ) -> Dict[str, Any]:
        finding = self.repo.get_finding_by_id(finding_id)
        if not finding:
            raise EntityNotFoundException("Finding", finding_id)

        scan = self.repo.get(finding.scan_id)
        if scan and scan.user_id and user_id and not is_admin and scan.user_id != user_id:
            raise AuthorizationException("Access denied: You cannot modify this finding.")

        updated = self.repo.update_finding_validation(finding_id, status, explanation)
        return {
            "id": updated.id,
            "remediationStatus": updated.remediation_status,
            "remediationExplanation": updated.remediation_explanation,
        }
