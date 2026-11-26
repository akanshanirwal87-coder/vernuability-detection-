import os
import uuid
import json
import time
from typing import Optional, Dict, Any, Callable
from sqlalchemy.orm import Session

from integrations.github_client import GitHubClient
from integrations.github_repository import GitHubRepositoryService
from integrations.repository_validator import RepositoryValidator
from integrations.repository_downloader import RepositoryDownloader
from integrations.repository_file_filter import RepositoryFileFilter
from services.repository_analysis_service import RepositoryAnalysisService, RepositoryAnalysisResult
from db.repositories.scan_repository import ScanRepository
from ml_engine.classifier import vulnerability_classifier
from core.logging_config import logger


class RepositoryScanService:
    """Orchestrates end-to-end repository validation, acquisition, analysis, and persistence."""

    def __init__(self, db: Session, github_token: Optional[str] = None):
        self.db = db
        self.repo = ScanRepository(db)
        self.github_client = GitHubClient(token=github_token)
        self.github_repo_service = GitHubRepositoryService(self.github_client)
        self.downloader = RepositoryDownloader(self.github_client)
        self.analysis_service = RepositoryAnalysisService()

    def execute_repository_scan(
        self,
        repository_url: str,
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Execute full pipeline:
        Validate URL -> Resolve Commit -> Download -> Filter -> Analyze -> Persist -> Cleanup.
        """
        # 1. Validate URL & host
        owner, repo = RepositoryValidator.validate_url(repository_url)

        # 2. Resolve target ref and commit SHA
        target_ref = commit_sha or branch or "main"
        try:
            resolved_sha = self.github_repo_service.resolve_ref_commit_sha(owner, repo, target_ref)
        except Exception as e:
            logger.warning("Could not resolve ref on GitHub API (%s), utilizing ref literal: %s", str(e), target_ref)
            resolved_sha = target_ref

        active_scan_id = scan_id or f"scan-repo-{uuid.uuid4().hex[:8]}"
        project_name = f"{owner}/{repo}"

        extracted_dir: Optional[str] = None

        try:
            # 3. Securely download and extract archive
            extracted_dir, _ = self.downloader.download_and_extract(owner, repo, resolved_sha)

            # 4. Filter scannable files
            file_collection = RepositoryFileFilter.collect_scannable_files(extracted_dir)
            scannable_files = file_collection["scannable_files"]
            skipped_files = file_collection["skipped_files"]

            # 5. Analyze repository files
            analysis_result: RepositoryAnalysisResult = self.analysis_service.analyze_repository(
                base_dir=extracted_dir,
                files_to_scan=scannable_files,
                scan_id=active_scan_id,
                progress_callback=progress_callback
            )

            # Combine filter skipped files with analysis skipped files
            total_skipped = skipped_files + analysis_result.skipped_files

            # ML model summary sourced dynamically from trained artifact metadata
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

            # 6. Persist to Database (update existing queued record or create if direct invocation)
            source_summary = (
                f"# Repository: {repository_url}\n"
                f"# Commit: {resolved_sha}\n"
                f"# Scanned files: {analysis_result.scanned_files_count}"
            )
            display_file_name = f"{project_name}@{resolved_sha[:7]} ({analysis_result.scanned_files_count} files)"

            existing_scan = self.repo.get(active_scan_id)
            if not existing_scan:
                self.repo.create_scan(
                    scan_id=active_scan_id,
                    project_name=project_name,
                    file_name=display_file_name,
                    language="multi-language",
                    source_code=source_summary,
                    project_id=project_id,
                    user_id=user_id,
                )
            else:
                existing_scan.project_name = project_name
                existing_scan.file_name = display_file_name
                existing_scan.language = "multi-language"
                existing_scan.source_code = source_summary

            self.repo.complete_scan(
                scan_id=active_scan_id,
                status="COMPLETED",
                duration_ms=analysis_result.duration_ms,
                lines_analyzed=analysis_result.total_lines_analyzed,
                highest_severity=analysis_result.highest_severity,
                risk_score=int(analysis_result.risk_report.get("overallScore", 0)),
                findings_count=analysis_result.findings_count,
                ast_summary=analysis_result.ast_summary,
                ml_analysis=ml_analysis,
            )

            if analysis_result.findings:
                self.repo.add_findings(active_scan_id, analysis_result.findings)

            return {
                "id": active_scan_id,
                "projectName": project_name,
                "repositoryUrl": repository_url,
                "branch": branch or "main",
                "commitSha": resolved_sha,
                "status": "COMPLETED",
                "durationMs": analysis_result.duration_ms,
                "scannedFilesCount": analysis_result.scanned_files_count,
                "totalFilesFound": file_collection["total_files_found"],
                "totalLinesAnalyzed": analysis_result.total_lines_analyzed,
                "highestSeverity": analysis_result.highest_severity,
                "findingsCount": analysis_result.findings_count,
                "findings": analysis_result.findings,
                "skippedFiles": total_skipped,
                "astSummary": analysis_result.ast_summary,
                "mlAnalysis": ml_analysis,
                "riskScore": int(analysis_result.risk_report.get("overallScore", 0)),
            }

        finally:
            # 7. Safe cleanup of isolated temporary extraction directory
            if extracted_dir:
                self.downloader.cleanup(extracted_dir)
