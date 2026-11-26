import json
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session

from core.exceptions import EntityNotFoundException, AuthorizationException
from db.repositories.scan_repository import ScanRepository


class ReportService:
    """Service compiling executive security audit reports and recommendations."""

    def __init__(self, db: Session):
        self.db = db
        self.repo = ScanRepository(db)

    def generate_report(
        self,
        scan_id: str,
        user_id: str = None,
        is_admin: bool = False,
    ) -> Dict[str, Any]:
        scan = self.repo.get(scan_id)
        if not scan:
            raise EntityNotFoundException("Scan", scan_id)

        if not is_admin and (not user_id or not scan.user_id or scan.user_id != user_id):
            raise AuthorizationException("Access denied: You cannot generate a report for this scan.")

        counts = json.loads(scan.findings_count_json) if scan.findings_count_json else {}
        total = counts.get("total", 0)
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)

        risk_score = min(100, crit * 30 + high * 15 + max(0, total - crit - high) * 5)

        recommendations = [
            "Enforce prepared statements with parameterized inputs to eliminate SQL Injection (CWE-89).",
            "Avoid shell=True in subprocess executions; use strict argument arrays (CWE-78).",
            "Store secrets and API tokens in environment variables or secret vaults (CWE-798).",
            "Perform automated Software Composition Analysis against OSV.dev for vulnerable third-party dependencies.",
            "Sanitize uploaded filenames with canonical path containment to prevent directory traversal (CWE-22)."
        ]

        return {
            "scanId": scan.id,
            "projectName": scan.project_name,
            "fileName": scan.file_name,
            "language": scan.language,
            "riskScore": risk_score,
            "highestSeverity": scan.highest_severity,
            "totalFindings": total,
            "criticalFindings": crit,
            "highFindings": high,
            "executiveSummary": (
                f"Security audit completed for {scan.project_name} ({scan.file_name}). "
                f"Identified {total} potential vulnerability findings, with {crit} Critical and {high} High severity items."
            ),
            "recommendations": recommendations,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
