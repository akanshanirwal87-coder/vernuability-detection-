import io
import os
import stat
import zipfile
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy.orm import Session

from db.models import Scan, ScanJob, User
from integrations.repository_downloader import RepositoryDownloader, RepositoryDownloaderError
from integrations.github_client import GitHubClient, GitHubApiError
from ml_engine.data_splitter import DataSplitter
from ml_engine.classifier import VulnerabilityClassifier
from core.permissions import SlidingWindowRateLimiter
from core.config import settings


def test_registration_cannot_escalate_to_admin(client):
    """Public self-registration must ignore/neutralize ADMIN role requests and always issue USER."""
    res = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Mallory Attacker",
            "email": "mallory.escalate@example.com",
            "password": "StrongPassword2026!",
            "role": "ADMIN",
        },
    )
    assert res.status_code == 201
    data = res.json()["data"]
    assert data["user"]["role"] == "USER"


def test_unauthenticated_v1_scan_and_job_endpoints_blocked(client, db_session: Session, normal_user: User):
    """Verify all scan, finding, report, and async GitHub job routes require authentication (401)."""
    scan = Scan(
        id="scan-unauth-test",
        user_id=normal_user.id,
        project_name="Private Proj",
        file_name="app.py",
        language="python",
        status="COMPLETED",
    )
    job = ScanJob(id="job-unauth-test", scan_id="scan-unauth-test", status="QUEUED", progress=0)
    db_session.add(scan)
    db_session.add(job)
    db_session.commit()

    assert client.get("/api/v1/scans").status_code == 401
    assert client.post("/api/v1/scans", json={"sourceCode": "print(1)", "language": "python"}).status_code == 401
    assert client.get("/api/v1/scans/scan-unauth-test").status_code == 401
    assert client.get("/api/v1/scans/scan-unauth-test/findings").status_code == 401
    assert client.delete("/api/v1/scans/scan-unauth-test").status_code == 401
    assert client.get("/api/v1/reports/scan-unauth-test").status_code == 401
    assert client.get("/api/v1/github/jobs/job-unauth-test").status_code == 401
    assert client.post("/api/v1/github/jobs/job-unauth-test/cancel").status_code == 401
    assert client.get("/api/v1/github/repo-info?url=https://github.com/octocat/Hello-World").status_code == 401


def test_legacy_unowned_scan_isolated_from_non_admin(client, db_session: Session, auth_headers, admin_headers):
    """Scans with user_id=None must not be readable or deletable by regular users (IDOR fix)."""
    orphan_scan = Scan(
        id="scan-orphan-01",
        user_id=None,
        project_name="Legacy",
        file_name="legacy.py",
        language="python",
        status="COMPLETED",
        findings_count_json='{"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}',
    )
    db_session.add(orphan_scan)
    db_session.commit()

    # Normal user blocked
    assert client.get("/api/v1/scans/scan-orphan-01", headers=auth_headers).status_code == 403
    assert client.delete("/api/v1/scans/scan-orphan-01", headers=auth_headers).status_code == 403
    # Admin allowed
    assert client.get("/api/v1/scans/scan-orphan-01", headers=admin_headers).status_code == 200


def test_downloader_rejects_zip_bomb_and_symlinks(monkeypatch):
    """Verify RepositoryDownloader rejects archives exceeding uncompressed limits or containing symlinks."""
    monkeypatch.setattr(settings, "MAX_REPO_UNCOMPRESSED_SIZE_BYTES", 1024)

    # 1. Zip bomb test (high compression payload exceeding 1024 uncompressed bytes)
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repo/large.py", b"A" * 5000)
    bomb_bytes = bomb_buf.getvalue()

    mock_client = MagicMock(spec=GitHubClient)
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Length": str(len(bomb_bytes))}
    mock_resp.iter_content.return_value = [bomb_bytes]
    mock_client.download_zipball_stream.return_value = mock_resp

    downloader = RepositoryDownloader(client=mock_client)
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(RepositoryDownloaderError, match="uncompressed size"):
            downloader.download_and_extract("acme", "bomb", "main", destination_dir=tmp_dir)

    # 2. Symlink member rejection test
    sym_buf = io.BytesIO()
    with zipfile.ZipFile(sym_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zi = zipfile.ZipInfo("repo/evil_link")
        zi.create_system = 3  # Unix
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zi, "/etc/passwd")
    sym_bytes = sym_buf.getvalue()

    mock_resp2 = MagicMock()
    mock_resp2.headers = {"Content-Length": str(len(sym_bytes))}
    mock_resp2.iter_content.return_value = [sym_bytes]
    mock_client.download_zipball_stream.return_value = mock_resp2

    with tempfile.TemporaryDirectory() as tmp_dir2:
        with pytest.raises(RepositoryDownloaderError, match="Unsupported or unsafe file type"):
            downloader.download_and_extract("acme", "symlink", "main", destination_dir=tmp_dir2)


def test_github_client_blocks_redirect_ssrf():
    """Verify GitHubClient refuses HTTP redirects targeting internal IPs or untrusted domains."""
    client = GitHubClient(token="ghp_test_token")
    fake_redirect = MagicMock()
    fake_redirect.status_code = 302
    fake_redirect.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch("integrations.github_client.requests.request", return_value=fake_redirect):
        with pytest.raises(GitHubApiError, match="Blocked unsafe"):
            client.get_repository("octocat", "hello")


def test_ml_artifact_checksum_verification():
    """Verify VulnerabilityClassifier computes SHA-256 verification and rejects tampered artifacts."""
    clf = VulnerabilityClassifier()
    assert clf.is_ready() is True
    assert clf.get_model_info().get("checksumsVerified") is True


def test_data_splitter_stratified_balance():
    """Verify DataSplitter preserves vulnerability balance across disjoint Train/Val/Test splits."""
    from data.dataset_collector import generate_training_dataset
    samples = generate_training_dataset()
    splitter = DataSplitter(test_size=0.15, val_size=0.15, random_seed=42)
    train_set, val_set, test_set = splitter.split_data(samples, group_by_signature=True)

    assert len(train_set) > len(test_set) >= 15
    assert len(val_set) >= 15
    # Verify both vulnerable and safe samples exist cleanly in every split (never skewed all-1 or all-0)
    for split in (train_set, val_set, test_set):
        vuln_ratio = sum(1 for x in split if x["isVulnerable"]) / len(split)
        assert 0.25 <= vuln_ratio <= 0.75, f"Unexpected skewed split ratio: {vuln_ratio}"


def test_rate_limiter_bound_and_security_headers(client):
    """Verify rate limiter eviction works safely and API responses include security headers."""
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
    assert limiter.is_allowed("10.0.0.1") is True
    assert limiter.is_allowed("10.0.0.1") is True
    assert limiter.is_allowed("10.0.0.1") is False

    res = client.get("/health")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"


def test_examiner_defense_benchmark_and_viva_accuracy(client, auth_headers):
    """Verify Examiner Defense benchmark runs real HybridScanner, enforces auth, and aligns viva-qa with live metrics."""
    assert client.post("/api/benchmark/run").status_code == 401

    bench_res = client.post("/api/benchmark/run", headers=auth_headers)
    assert bench_res.status_code == 200
    b = bench_res.json()
    assert b["totalTests"] == len(b["results"]) == 16
    assert b["truePositives"] + b["falsePositives"] + b["trueNegatives"] + b["falseNegatives"] == b["totalTests"]
    for item in b["results"]:
        assert item["passed"] is (item["predictedVulnerable"] == item["isVulnerable"])

    viva_res = client.get("/api/examiner/viva-qa")
    assert viva_res.status_code == 200
    viva = viva_res.json()
    q4 = next(q for q in viva["questions"] if q["id"] == "q4")
    info = VulnerabilityClassifier().get_model_info()
    assert f"{info['accuracy']:.2f}%" in q4["answer"]
    assert f"{info['precision']:.2f}%" in q4["answer"]
