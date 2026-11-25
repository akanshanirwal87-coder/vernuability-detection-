import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session

from workers.scan_tasks import scan_repository_task
from db.models import Scan, ScanJob


def test_scan_repository_task_success(db_session: Session):
    """Test Celery scan_repository_task marks job and scan COMPLETED with findings."""
    job_id = "test-job-celery-01"
    scan_id = "test-scan-celery-01"

    # Seed Scan and ScanJob
    scan = Scan(
        id=scan_id,
        file_name="https://github.com/acme/app (main)",
        language="repository",
        status="QUEUED",
    )
    job = ScanJob(
        id=job_id,
        scan_id=scan_id,
        status="QUEUED",
        progress=0,
    )
    db_session.add(scan)
    db_session.add(job)
    db_session.commit()

    mock_analysis_result = {
        "scanId": scan_id,
        "findings": [
            {
                "id": "f-1",
                "title": "SQL Injection",
                "cwe_id": "CWE-89",
                "severity": "CRITICAL",
                "file_path": "db.py",
                "line_number": 10,
                "confidence": 0.95,
            }
        ],
        "scannedFilesCount": 5,
        "highestSeverity": "CRITICAL",
        "riskScore": 85,
    }

    # Patch close() to prevent closing the shared test db_session
    with patch.object(db_session, "close", lambda: None), \
         patch("workers.scan_tasks.SessionLocal", return_value=db_session), \
         patch("workers.scan_tasks.RepositoryScanService") as mock_scanner_cls:

        mock_scanner = MagicMock()
        mock_scanner.execute_repository_scan.return_value = mock_analysis_result
        mock_scanner_cls.return_value = mock_scanner

        # Run task synchronously
        res = scan_repository_task.apply(args=[
            job_id,
            scan_id,
            "https://github.com/acme/app",
            "main",
        ]).get()

        assert res["status"] == "COMPLETED"
        assert res["total_findings"] == 1
        assert res["highest_severity"] == "CRITICAL"

        # Check DB updates on db_session
        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "COMPLETED"
        assert job.progress == 100
        assert scan.status == "COMPLETED"
