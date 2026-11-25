import time
import json
from typing import Optional, Dict, Any
from celery.exceptions import SoftTimeLimitExceeded

from workers.celery_app import celery_app
from db.database import SessionLocal
from db.models import Scan, ScanJob
from services.repository_scan_service import RepositoryScanService
from core.logging_config import logger


@celery_app.task(bind=True, name="scan_repository_task", max_retries=2)
def scan_repository_task(
    self,
    job_id: str,
    scan_id: str,
    repository_url: str,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
    project_id: Optional[str] = None,
    user_id: Optional[str] = None,
    github_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Background task executing repository validation, download, multi-file analysis, and DB persistence."""
    logger.info("Starting background scan task: job=%s, scan=%s, repo=%s", job_id, scan_id, repository_url)
    db = SessionLocal()

    try:
        # Update job to RUNNING
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "RUNNING"
            job.progress = 5
            db.commit()

        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "RUNNING"
            db.commit()

        # Progress tracking callback
        def progress_callback(processed: int, total: int, findings_found: int):
            pct = 10 + int((processed / max(1, total)) * 80)
            self.update_state(
                state="RUNNING",
                meta={
                    "processed_files": processed,
                    "total_files": total,
                    "findings_count": findings_found,
                    "progress": pct,
                }
            )
            # Update database periodically
            try:
                j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
                if j:
                    j.progress = pct
                    db.commit()
            except Exception:
                db.rollback()

        scanner = RepositoryScanService(db=db, github_token=github_token)
        result = scanner.execute_repository_scan(
            repository_url=repository_url,
            branch=branch,
            commit_sha=commit_sha,
            project_id=project_id,
            user_id=user_id,
            scan_id=scan_id,
            progress_callback=progress_callback,
        )

        # Mark job and scan as COMPLETED
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            db.commit()

        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "COMPLETED"
            db.commit()

        logger.info("Scan task completed successfully: job=%s, findings=%d", job_id, len(result.get("findings", [])))
        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "scan_id": scan_id,
            "total_findings": len(result.get("findings", [])),
            "highest_severity": result.get("highestSeverity", "LOW"),
            "risk_score": result.get("riskScore", 0),
        }

    except SoftTimeLimitExceeded:
        logger.error("Scan task soft time limit exceeded for job %s", job_id)
        _record_job_failure(db, job_id, scan_id, "Scan timed out: Execution exceeded permitted time threshold.")
        return {"status": "FAILED", "error": "Execution timed out"}

    except Exception as exc:
        logger.error("Scan task failed for job %s: %s", job_id, str(exc), exc_info=True)
        # Check if transient error suitable for retry
        err_msg = str(exc)
        is_transient = "rate limit" in err_msg.lower() or "connection" in err_msg.lower()

        if is_transient and self.request.retries < self.max_retries:
            db.close()
            raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))

        _record_job_failure(db, job_id, scan_id, f"Scan failed: {err_msg}")
        return {"status": "FAILED", "error": err_msg}

    finally:
        db.close()


def _record_job_failure(db, job_id: str, scan_id: str, error_message: str) -> None:
    """Safely records failure states in database."""
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "FAILED"
            job.error_message = error_message
            db.commit()

        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "FAILED"
            db.commit()
    except Exception as e:
        logger.error("Failed to persist job failure state: %s", str(e))
        db.rollback()
