import uuid
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from db.models import Scan, ScanJob
from db.repositories.project_repository import ProjectRepository
from workers.scan_tasks import scan_repository_task
from integrations.repository_validator import RepositoryValidator, RepositoryValidationError
from core.exceptions import ValidationException, EntityNotFoundException, AuthorizationException
from core.security import encrypt_secret
from core.logging_config import logger


class ScanQueueService:
    """Manages idempotent background scan submission with Celery and database tracking."""

    def __init__(self, db: Session):
        self.db = db

    def enqueue_repository_scan(
        self,
        repository_url: str,
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        github_token: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Idempotently enqueue a repository scan job.
        If an active job already exists for the same user, repo, and ref, returns the active job.
        """
        try:
            RepositoryValidator.validate_url(repository_url)
            if branch:
                branch = RepositoryValidator.validate_branch(branch)
        except RepositoryValidationError as e:
            raise ValidationException(str(e))

        if project_id:
            project = ProjectRepository(self.db).get(project_id)
            if not project:
                raise EntityNotFoundException("Project", project_id)
            if user_id and project.user_id != user_id:
                raise AuthorizationException("Access denied: You do not own the target project.")

        target_ref = commit_sha or branch or "main"
        expected_file_name = f"{repository_url} ({target_ref})"

        # 1. User-scoped exact Idempotency Check: check for existing in-flight job
        if not force:
            query = self.db.query(Scan).filter(
                Scan.file_name == expected_file_name,
                Scan.status.in_(["PENDING", "QUEUED", "RUNNING"]),
            )
            if user_id:
                query = query.filter(Scan.user_id == user_id)
            else:
                query = query.filter(Scan.user_id.is_(None))

            active_scan = query.order_by(Scan.created_at.desc()).first()
            if active_scan:
                active_job = self.db.query(ScanJob).filter(ScanJob.scan_id == active_scan.id).first()
                job_id = active_job.id if active_job else f"job-{active_scan.id}"
                logger.info("Found active in-flight scan for repo %s: %s", repository_url, active_scan.id)
                return {
                    "job_id": job_id,
                    "jobId": job_id,
                    "scan_id": active_scan.id,
                    "scanId": active_scan.id,
                    "status": active_scan.status,
                    "progress": active_job.progress if active_job else 10,
                    "is_duplicate": True,
                    "isDuplicate": True,
                    "message": "An active scan is already in progress for this repository and branch.",
                }

        # 2. Create DB Scan and ScanJob entities
        scan_id = f"scan-repo-{uuid.uuid4().hex[:8]}"
        job_id = f"job-{uuid.uuid4().hex[:8]}"

        scan_record = Scan(
            id=scan_id,
            project_id=project_id,
            user_id=user_id,
            project_name=repository_url.split("/")[-1].replace(".git", ""),
            file_name=expected_file_name,
            language="repository",
            status="QUEUED",
        )
        self.db.add(scan_record)

        job_record = ScanJob(
            id=job_id,
            scan_id=scan_id,
            status="QUEUED",
            progress=0,
        )
        self.db.add(job_record)
        self.db.commit()

        # Encrypt token before serialization to Celery broker
        encrypted_token = encrypt_secret(github_token)

        # 3. Dispatch to Celery background worker pinned to task_id=job_id
        task_kwargs = {
            "job_id": job_id,
            "scan_id": scan_id,
            "repository_url": repository_url,
            "branch": branch,
            "commit_sha": commit_sha,
            "project_id": project_id,
            "user_id": user_id,
            "github_token": encrypted_token,
        }
        try:
            scan_repository_task.apply_async(kwargs=task_kwargs, task_id=job_id)
            logger.info("Successfully enqueued scan task to Celery: job=%s, scan=%s", job_id, scan_id)
        except Exception as e:
            logger.warning("Celery dispatch failed (%s); falling back to synchronous execution", str(e))
            try:
                scan_repository_task(**task_kwargs)
            except Exception as sync_exc:
                logger.error("Synchronous scan fallback also failed: %s", str(sync_exc))

        return {
            "job_id": job_id,
            "jobId": job_id,
            "scan_id": scan_id,
            "scanId": scan_id,
            "status": "QUEUED",
            "progress": 0,
            "is_duplicate": False,
            "isDuplicate": False,
        }
