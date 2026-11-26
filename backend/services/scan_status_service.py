from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from celery.result import AsyncResult

from db.models import ScanJob, Scan, Finding
from workers.celery_app import celery_app
from core.exceptions import EntityNotFoundException, AuthorizationException
from core.logging_config import logger


class ScanStatusService:
    """Provides real-time inspection, progress tracking, and job cancellation."""

    def __init__(self, db: Session):
        self.db = db

    def get_status(self, job_id: str, user_id: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
        """Fetch current status and progress of a scan job with strict ownership checks."""
        job = self.db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            raise EntityNotFoundException("ScanJob", job_id)

        scan = self.db.query(Scan).filter(Scan.id == job.scan_id).first()
        if not is_admin and (not scan or not user_id or not scan.user_id or scan.user_id != user_id):
            raise AuthorizationException("Access denied: You do not have permission to view this scan job.")

        # Check Celery task state for live metadata if in-progress
        meta_data: Dict[str, Any] = {}
        try:
            res = AsyncResult(job_id, app=celery_app)
            if isinstance(res.info, dict):
                meta_data = res.info
        except Exception:
            pass

        findings_count = meta_data.get("findings_count")
        if findings_count is None and scan:
            findings_count = self.db.query(func.count(Finding.id)).filter(Finding.scan_id == scan.id).scalar() or 0

        return {
            "jobId": job.id,
            "scanId": job.scan_id,
            "status": job.status,
            "progress": job.progress,
            "errorMessage": job.error_message,
            "processedFiles": meta_data.get("processed_files", 0),
            "totalFiles": meta_data.get("total_files", 0),
            "findingsDiscovered": findings_count or 0,
            "highestSeverity": scan.highest_severity if scan else "LOW",
            "createdAt": job.created_at.isoformat() if job.created_at else None,
            "updatedAt": job.updated_at.isoformat() if job.updated_at else None,
        }

    def cancel_job(self, job_id: str, user_id: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
        """Revoke a background Celery task and mark job as CANCELLED after verifying ownership."""
        job = self.db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            raise EntityNotFoundException("ScanJob", job_id)

        scan = self.db.query(Scan).filter(Scan.id == job.scan_id).first()
        if not is_admin and (not scan or not user_id or not scan.user_id or scan.user_id != user_id):
            raise AuthorizationException("Access denied: You cannot cancel this scan job.")

        try:
            celery_app.control.revoke(job_id, terminate=True, signal="SIGTERM")
        except Exception as e:
            logger.warning("Could not revoke Celery task %s: %s", job_id, str(e))

        job.status = "CANCELLED"
        job.error_message = "Scan was cancelled by user request."

        if scan and scan.status in ("PENDING", "QUEUED", "RUNNING"):
            scan.status = "CANCELLED"

        self.db.commit()
        return {"jobId": job.id, "status": "CANCELLED"}
