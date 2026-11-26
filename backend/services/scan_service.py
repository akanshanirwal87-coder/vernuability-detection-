import time
import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from core.exceptions import EntityNotFoundException, AuthorizationException, ValidationException
from db.models import Scan, Finding, ScanJob
from db.repositories.scan_repository import ScanRepository
from db.repositories.project_repository import ProjectRepository
from analyzer.python_ast_scanner import PythonAstScanner
from analyzer.javascript_scanner import JavaScriptScanner
from analyzer.dependency_parser import DependencyParser
from analyzer.sca_scanner import sca_scanner
from analyzer.manageengine_client import manageengine_client
from analyzer.hybrid_scanner import HybridScanner
from analyzer.risk_assessment import RiskAssessment
from ml_engine.classifier import vulnerability_classifier


def calculate_highest_severity(findings: List[Dict[str, Any]]) -> str:
    severities = [f.get("severity", "LOW") for f in findings]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


def count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for f in findings:
        sev = f.get("severity", "LOW").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


class ScanService:
    """Orchestrates AST, AI/ML, SCA, and ManageEngine rule detection and database persistence."""

    def __init__(self, db: Session):
        self.db = db
        self.repo = ScanRepository(db)

    def execute_scan(
        self,
        source_code: str,
        language: str,
        file_name: str = "source_code",
        project_name: str = "Direct Scan",
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        enable_ai: bool = True,
        enable_rules: bool = True,
    ) -> Dict[str, Any]:
        start_time = time.time()
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        lines_analyzed = len(source_code.splitlines())

        if project_id:
            project = ProjectRepository(self.db).get(project_id)
            if not project:
                raise EntityNotFoundException("Project", project_id)
            if user_id and project.user_id != user_id:
                raise AuthorizationException("Access denied: You do not own the specified project.")

        # Check if file is a dependency manifest
        is_manifest = DependencyParser.is_manifest_file(file_name) or language.lower() in ("manifest", "requirements", "toml", "lockfile")

        # 1. Multi-Technique Hybrid Analysis or Manifest SCA
        me_triggered = []
        if is_manifest:
            findings = sca_scanner.scan_manifest(file_name, source_code, scan_id)
            ast_summary = {
                "nodesCount": 0,
                "functionsFound": 0,
                "importsFound": [f.get("packageName") for f in findings if f.get("packageName")],
                "sinksIdentified": 0,
            }
            risk_report = RiskAssessment.evaluate_risk(findings).to_dict()
        elif language.lower() in ("python", "javascript", "typescript"):
            scanner = HybridScanner(
                source_code=source_code,
                language=language,
                file_name=file_name,
                enable_ast=True,
                enable_taint=True,
                enable_rules=enable_rules,
                enable_ml=enable_ai,
            )
            findings, ast_summary, risk_report = scanner.scan()
            if enable_rules:
                me_rules = manageengine_client.check_code_against_rules(source_code, language)
                me_triggered = me_rules
        else:
            raise ValidationException(f"Unsupported language: {language}")

        # Tag detection source and scanId
        for f in findings:
            if "scanId" not in f:
                f["scanId"] = scan_id

        duration_ms = max(int((time.time() - start_time) * 1000), 80)
        highest_severity = calculate_highest_severity(findings)
        findings_count = count_severities(findings)

        risk_score = risk_report.get("overallScore", 0.0)

        # ML Model metadata
        ml_info = vulnerability_classifier.get_model_info()
        ml_analysis = {
            "modelName": ml_info.get("modelName", "SecureCode-VulnNet"),
            "version": ml_info.get("version", "2.1.0-leakfree"),
            "accuracy": ml_info.get("accuracy", 0.0),
            "precision": ml_info.get("precision", 0.0),
            "recall": ml_info.get("recall", 0.0),
            "macroF1": ml_info.get("macroF1", ml_info.get("f1Score", 0.0)),
            "f1Score": ml_info.get("f1Score", ml_info.get("macroF1", 0.0)),
            "totalDatasetSamples": ml_info.get("totalSamples", 0),
        }

        # Persist Scan to Database
        scan_record = self.repo.create_scan(
            scan_id=scan_id,
            project_name=project_name,
            file_name=file_name,
            language=language,
            source_code=source_code,
            project_id=project_id,
            user_id=user_id,
        )

        self.repo.complete_scan(
            scan_id=scan_id,
            status="COMPLETED",
            duration_ms=duration_ms,
            lines_analyzed=lines_analyzed,
            highest_severity=highest_severity,
            risk_score=risk_score,
            findings_count=findings_count,
            ast_summary=ast_summary,
            ml_analysis=ml_analysis,
        )

        # Persist Findings
        self.repo.add_findings(scan_id=scan_id, findings=findings)

        return {
            "id": scan_id,
            "projectName": project_name,
            "fileName": file_name,
            "language": language,
            "status": "COMPLETED",
            "riskScore": risk_score,
            "highestSeverity": highest_severity,
            "durationMs": duration_ms,
            "linesAnalyzed": lines_analyzed,
            "findingsCount": findings_count,
            "findings": findings,
            "astSummary": ast_summary,
            "mlAnalysis": ml_analysis,
            "osvFindings": [f for f in findings if f.get("detectionSource") in ("SCA_OSV", "OSV_DATABASE")],
            "manageEngineRules": me_triggered,
            "createdAt": scan_record.created_at.isoformat(),
            "completedAt": scan_record.completed_at.isoformat() if scan_record.completed_at else None,
        }

    def list(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 20,
    ) -> Tuple[List[Dict[str, Any]], int]:
        scans, total = self.repo.list_scans(
            user_id=user_id,
            project_id=project_id,
            status=status,
            skip=skip,
            limit=limit,
        )
        items = []
        for s in scans:
            counts = json.loads(s.findings_count_json) if s.findings_count_json else {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
            items.append({
                "id": s.id,
                "projectId": s.project_id,
                "projectName": s.project_name,
                "fileName": s.file_name,
                "language": s.language,
                "status": s.status,
                "riskScore": s.risk_score,
                "highestSeverity": s.highest_severity,
                "durationMs": s.duration_ms,
                "linesAnalyzed": s.lines_analyzed,
                "findingsCount": counts,
                "createdAt": s.created_at.isoformat(),
                "completedAt": s.completed_at.isoformat() if s.completed_at else None,
            })
        return items, total

    def get_by_id(self, scan_id: str, user_id: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
        scan = self.repo.get(scan_id)
        if not scan:
            raise EntityNotFoundException("Scan", scan_id)

        # Enforce user isolation
        if not is_admin and (not user_id or not scan.user_id or scan.user_id != user_id):
            raise AuthorizationException("Access denied: You do not have permission to view this scan.")

        counts = json.loads(scan.findings_count_json) if scan.findings_count_json else {}
        ast_sum = json.loads(scan.ast_summary_json) if scan.ast_summary_json else {}
        ml_an = json.loads(scan.ml_analysis_json) if scan.ml_analysis_json else {}

        # Fetch all findings for this scan without silent 200-item truncation
        findings_objs, _ = self.repo.get_findings_paginated(scan_id, limit=10000)
        findings = []
        for f in findings_objs:
            findings.append({
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
            })

        return {
            "id": scan.id,
            "projectId": scan.project_id,
            "projectName": scan.project_name,
            "fileName": scan.file_name,
            "language": scan.language,
            "status": scan.status,
            "riskScore": scan.risk_score,
            "highestSeverity": scan.highest_severity,
            "durationMs": scan.duration_ms,
            "linesAnalyzed": scan.lines_analyzed,
            "sourceCode": scan.source_code,
            "findingsCount": counts,
            "findings": findings,
            "astSummary": ast_sum,
            "mlAnalysis": ml_an,
            "createdAt": scan.created_at.isoformat(),
            "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
        }

    def delete(self, scan_id: str, user_id: Optional[str] = None, is_admin: bool = False) -> None:
        scan = self.repo.get(scan_id)
        if not scan:
            raise EntityNotFoundException("Scan", scan_id)

        if not is_admin and (not user_id or not scan.user_id or scan.user_id != user_id):
            raise AuthorizationException("Access denied: You cannot delete this scan.")

        self.repo.delete(scan)
