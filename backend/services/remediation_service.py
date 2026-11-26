from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session

from core.exceptions import EntityNotFoundException, AuthorizationException
from db.repositories.scan_repository import ScanRepository
from analyzer.fix_validator import FixValidator


class RemediationService:
    """Service providing AST sandbox validation of code remediations."""

    def __init__(self, db: Session):
        self.db = db
        self.repo = ScanRepository(db)

    def validate_code_fix(
        self,
        scan_id: str,
        finding_id: str,
        proposed_code: str,
        user_id: str = None,
        is_admin: bool = False,
    ) -> Dict[str, Any]:
        scan = self.repo.get(scan_id)
        if not scan:
            raise EntityNotFoundException("Scan", scan_id)

        if not is_admin and (not user_id or not scan.user_id or scan.user_id != user_id):
            raise AuthorizationException("Access denied: You cannot modify this scan's findings.")

        finding = self.repo.get_finding_by_id(finding_id)
        if not finding or finding.scan_id != scan_id:
            raise EntityNotFoundException("Finding", finding_id)

        finding_dict = {
            "id": finding.id,
            "cwe": finding.cwe,
            "category": finding.category,
            "title": finding.title,
            "startLine": finding.start_line,
            "endLine": finding.end_line,
            "vulnerableCode": finding.vulnerable_code,
        }

        # Validate with AST sandbox
        if scan.language.lower() == "python":
            passed, status, msg = FixValidator.validate_python_fix(scan.source_code or "", proposed_code, finding_dict)
        else:
            passed, status, msg = FixValidator.validate_javascript_fix(scan.source_code or "", proposed_code, finding_dict)

        # Update in database
        self.repo.update_finding_validation(finding_id, status, msg)

        # Count remaining open findings
        open_findings, _ = self.repo.get_findings_paginated(scan_id, limit=10000)
        remaining = len([f for f in open_findings if f.remediation_status != "VALIDATION_PASSED"])

        return {
            "findingId": finding_id,
            "status": status,
            "passed": passed,
            "message": msg,
            "verifiedAt": datetime.now(timezone.utc).isoformat(),
            "remainingFindingsCount": remaining,
        }
