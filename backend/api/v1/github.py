from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Request, Header, HTTPException, Query, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from db.database import get_db
from core.permissions import get_current_user_optional, check_rate_limit
from schemas.common import ApiResponse
from integrations.repository_validator import RepositoryValidator, RepositoryValidationError
from integrations.github_webhooks import GitHubWebhookHandler
from integrations.github_repository import GitHubRepositoryService
from integrations.github_client import GitHubClient
from services.scan_queue import ScanQueueService
from services.scan_status_service import ScanStatusService
from core.logging_config import logger

router = APIRouter(prefix="/github", tags=["GitHub Integration & Async Repository Scanning"])


class GitHubScanRequest(BaseModel):
    repositoryUrl: str
    branch: Optional[str] = None
    commitSha: Optional[str] = None
    projectId: Optional[str] = None
    githubToken: Optional[str] = None
    force: bool = False


@router.post("/scan", response_model=ApiResponse[Dict[str, Any]], status_code=status.HTTP_202_ACCEPTED)
def enqueue_repository_scan(
    req: GitHubScanRequest,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
    _=Depends(check_rate_limit),
):
    """Enqueues an asynchronous repository vulnerability scan via Celery worker."""
    try:
        RepositoryValidator.validate_url(req.repositoryUrl)
    except RepositoryValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_id = current_user.get("id") if current_user else None
    queue_service = ScanQueueService(db)

    result = queue_service.enqueue_repository_scan(
        repository_url=req.repositoryUrl,
        branch=req.branch,
        commit_sha=req.commitSha,
        project_id=req.projectId,
        user_id=user_id,
        github_token=req.githubToken,
        force=req.force,
    )

    return ApiResponse(
        success=True,
        message="Repository scan enqueued for asynchronous background analysis.",
        data=result,
    )


@router.get("/jobs/{job_id}", response_model=ApiResponse[Dict[str, Any]])
def get_job_status(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve real-time execution status, file progress, and discovered findings for a scan job."""
    status_service = ScanStatusService(db)
    job_status = status_service.get_status(job_id)

    return ApiResponse(
        success=True,
        message="Scan job status retrieved successfully.",
        data=job_status,
    )


@router.post("/jobs/{job_id}/cancel", response_model=ApiResponse[Dict[str, Any]])
def cancel_scan_job(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Cancel an active or queued background scan job."""
    status_service = ScanStatusService(db)
    result = status_service.cancel_job(job_id)

    return ApiResponse(
        success=True,
        message="Scan job cancelled.",
        data=result,
    )


@router.get("/repo-info", response_model=ApiResponse[Dict[str, Any]])
def get_repository_info(
    url: str = Query(..., description="GitHub repository HTTPS URL"),
    token: Optional[str] = Query(None, description="Optional GitHub access token for private repos"),
):
    """Inspect and validate repository accessibility, default branch, and visibility."""
    try:
        owner, repo = RepositoryValidator.validate_url(url)
    except RepositoryValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    client = GitHubClient(token=token)
    repo_service = GitHubRepositoryService(client)

    try:
        details = repo_service.get_repo_details(owner, repo)
        branches = repo_service.list_branches(owner, repo)
        details["branches"] = branches[:20]
        return ApiResponse(
            success=True,
            message="Repository metadata resolved successfully.",
            data=details,
        )
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Could not access GitHub repository: {str(e)}")


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    db: Session = Depends(get_db),
):
    """
    Secure GitHub webhook receiver with HMAC-SHA256 signature verification.
    Automatically enqueues asynchronous scans for push and pull_request events.
    """
    payload_bytes = await request.body()

    # 1. Verify HMAC SHA-256 signature
    is_valid = GitHubWebhookHandler.verify_signature(payload_bytes, x_hub_signature_256)
    if not is_valid:
        logger.warning("Rejected webhook: invalid or missing HMAC signature.")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if not x_github_event:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Event header")

    payload = await request.json()
    event_data = GitHubWebhookHandler.parse_event(x_github_event, payload)

    if not event_data:
        return {"status": "ignored", "event": x_github_event, "reason": "Unsupported action or event type"}

    # 2. Idempotently enqueue scan
    queue_service = ScanQueueService(db)
    result = queue_service.enqueue_repository_scan(
        repository_url=event_data.repository_url,
        branch=event_data.ref.replace("refs/heads/", ""),
        commit_sha=event_data.commit_sha,
    )

    logger.info("Webhook dispatched scan: repo=%s, commit=%s, job=%s", event_data.repository_url, event_data.commit_sha, result.get("job_id"))
    return {
        "status": "queued",
        "event": x_github_event,
        "job": result,
    }
