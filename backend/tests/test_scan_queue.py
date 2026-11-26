import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session

from services.scan_queue import ScanQueueService
from db.models import Scan, ScanJob, User, Project


def test_enqueue_repository_scan_idempotency(db_session: Session, normal_user: User, second_user: User):
    """Test that submitting an identical repository URL while a scan is active returns the existing job per user."""
    queue_service = ScanQueueService(db=db_session)

    # 1. Enqueue first scan with sensitive github_token (verify Fernet encryption & pinned task_id)
    with patch("workers.scan_tasks.scan_repository_task.apply_async") as mock_celery:
        mock_task = MagicMock()
        mock_task.id = "celery-job-1"
        mock_celery.return_value = mock_task

        res1 = queue_service.enqueue_repository_scan(
            repository_url="https://github.com/torvalds/linux",
            branch="master",
            user_id=normal_user.id,
            github_token="ghp_secret_token_1234567890",
        )

        assert res1["status"] in ["QUEUED", "RUNNING"]
        scan_id1 = res1["scanId"]

        # Verify task_id matches DB job_id and token was not serialized in plaintext
        call_kwargs = mock_celery.call_args.kwargs
        assert call_kwargs["task_id"] == res1["jobId"]
        queued_token = call_kwargs["kwargs"]["github_token"]
        assert queued_token.startswith("enc:v1:")
        assert "ghp_secret_token_1234567890" not in queued_token

        # 2. Enqueue same repo again for same user -> Should return existing job
        res2 = queue_service.enqueue_repository_scan(
            repository_url="https://github.com/torvalds/linux",
            branch="master",
            user_id=normal_user.id,
            force=False,
        )

        assert res2["scanId"] == scan_id1
        assert res2.get("isDuplicate") is True
        assert res2.get("message") == "An active scan is already in progress for this repository and branch."

        # 3. Different user enqueueing same repo must get their own isolated job (never share another user's job_id)
        res3 = queue_service.enqueue_repository_scan(
            repository_url="https://github.com/torvalds/linux",
            branch="master",
            user_id=second_user.id,
            force=False,
        )
        assert res3["scanId"] != scan_id1
        assert res3.get("isDuplicate") is not True


def test_enqueue_repository_scan_force_creates_new(db_session: Session, normal_user: User):
    """Test that force=True bypasses idempotency duplicate check."""
    queue_service = ScanQueueService(db=db_session)

    with patch("workers.scan_tasks.scan_repository_task.apply_async") as mock_celery:
        mock_task = MagicMock()
        mock_task.id = "celery-job-force-1"
        mock_celery.return_value = mock_task

        res1 = queue_service.enqueue_repository_scan(
            repository_url="https://github.com/acme/app",
            branch="main",
            user_id=normal_user.id,
        )

        mock_task2 = MagicMock()
        mock_task2.id = "celery-job-force-2"
        mock_celery.return_value = mock_task2

        res2 = queue_service.enqueue_repository_scan(
            repository_url="https://github.com/acme/app",
            branch="main",
            user_id=normal_user.id,
            force=True,
        )

        assert res1["scanId"] != res2["scanId"]
        assert res2.get("isDuplicate") is not True
