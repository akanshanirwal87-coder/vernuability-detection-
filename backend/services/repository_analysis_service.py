import os
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from analyzer.hybrid_scanner import HybridScanner
from analyzer.manageengine_client import manageengine_client
from analyzer.dependency_parser import DependencyParser
from analyzer.sca_scanner import sca_scanner
from analyzer.risk_assessment import RiskAssessment
from ml_engine.classifier import vulnerability_classifier
from core.logging_config import logger


@dataclass
class RepositoryAnalysisResult:
    scan_id: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    scanned_files_count: int = 0
    total_lines_analyzed: int = 0
    skipped_files: List[Dict[str, Any]] = field(default_factory=list)
    ast_summary: Dict[str, Any] = field(default_factory=dict)
    risk_report: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    highest_severity: str = "LOW"
    findings_count: Dict[str, int] = field(default_factory=dict)


class RepositoryAnalysisService:
    """Analyzes a multi-file repository codebase using Hybrid AST, Taint, ML, and SCA scanners."""

    @staticmethod
    def detect_file_language(file_path: str) -> Optional[str]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".py":
            return "python"
        elif ext in (".js", ".jsx"):
            return "javascript"
        elif ext in (".ts", ".tsx"):
            return "typescript"
        elif os.path.basename(file_path).lower() in (
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
        ):
            return "manifest"
        return None

    def analyze_repository(
        self,
        base_dir: Optional[str] = None,
        files_to_scan: Optional[List[Dict[str, Any]]] = None,
        scan_id: Optional[str] = None,
        progress_callback: Optional[callable] = None,
        repo_root: Optional[str] = None,
    ) -> RepositoryAnalysisResult:
        start_time = time.time()
        all_findings: List[Dict[str, Any]] = []
        skipped_during_analysis: List[Dict[str, Any]] = []
        total_lines = 0

        root = base_dir or repo_root
        if not root:
            raise ValueError("base_dir or repo_root must be provided.")

        actual_scan_id = scan_id or f"scan-repo-{int(time.time())}"

        if files_to_scan is None:
            from integrations.repository_file_filter import RepositoryFileFilter
            filtered = RepositoryFileFilter.collect_scannable_files(root)
            files_to_scan = filtered["scannable_files"]

        total_files = len(files_to_scan)

        for idx, file_meta in enumerate(files_to_scan, start=1):
            rel_path = file_meta["rel_path"]
            abs_path = file_meta.get("abs_path") or file_meta.get("full_path") or os.path.join(root, rel_path)
            category = file_meta.get("category", "")

            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                lines_in_file = len(content.splitlines())
                total_lines += lines_in_file

                lang = self.detect_file_language(rel_path)
                if lang == "manifest":
                    manifest_findings = self._scan_manifest_file(rel_path, content, actual_scan_id)
                    all_findings.extend(manifest_findings)
                elif lang in ("python", "javascript", "typescript"):
                    scanner = HybridScanner(
                        source_code=content,
                        language=lang,
                        file_name=rel_path,
                    )
                    file_findings, file_ast, _ = scanner.scan()
                    for f in file_findings:
                        f["file"] = rel_path
                        f["file_path"] = rel_path
                        f["scanId"] = actual_scan_id
                        all_findings.append(f)
                else:
                    skipped_during_analysis.append({"path": rel_path, "reason": f"Unsupported language '{lang}'"})

            except Exception as e:
                logger.warning("Error analyzing repository file '%s': %s", rel_path, str(e))
                skipped_during_analysis.append({"path": rel_path, "reason": f"Read/Parse error: {str(e)}"})

            if progress_callback:
                try:
                    progress_callback(idx, total_files, len(all_findings))
                except Exception as cb_err:
                    logger.debug("Progress callback error: %s", cb_err)

        # Deduplicate findings
        deduped_findings = self._deduplicate_findings(all_findings)

        # Compute lowercase severity breakdown consistent with ScanService / ScanResponseModel
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(deduped_findings)}
        highest_sev = "LOW"
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for f in deduped_findings:
            sev = str(f.get("severity", "LOW")).upper()
            sev_lower = sev.lower()
            if sev_lower in severity_counts:
                severity_counts[sev_lower] += 1
            if sev_rank.get(sev, 0) > sev_rank.get(highest_sev, 0):
                highest_sev = sev

        # Calculate risk score
        risk_report_obj = RiskAssessment.evaluate_risk(deduped_findings)
        risk_score = risk_report_obj.overall_score
        risk_report = risk_report_obj.to_dict()

        duration_ms = int((time.time() - start_time) * 1000)

        return RepositoryAnalysisResult(
            scan_id=actual_scan_id,
            findings=deduped_findings,
            scanned_files_count=len(files_to_scan),
            total_lines_analyzed=total_lines,
            skipped_files=skipped_during_analysis,
            ast_summary={"totalFilesScanned": len(files_to_scan), "totalLines": total_lines},
            risk_report=risk_report,
            duration_ms=duration_ms,
            highest_severity=highest_sev,
            findings_count=severity_counts,
        )

    def _scan_manifest_file(self, rel_path: str, content: str, scan_id: str = "sca") -> List[Dict[str, Any]]:
        try:
            findings = sca_scanner.scan_manifest(os.path.basename(rel_path), content, scan_id)
            for f in findings:
                f["file"] = rel_path
                f["file_path"] = rel_path
                f["scanId"] = scan_id
            return findings
        except Exception as e:
            logger.warning("Error parsing dependency manifest '%s': %s", rel_path, str(e))
            return []

    @staticmethod
    def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in findings:
            key = (
                f.get("file") or f.get("file_path") or "",
                f.get("startLine") or f.get("line_number") or 0,
                f.get("cwe") or f.get("cwe_id") or "",
                f.get("title", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
