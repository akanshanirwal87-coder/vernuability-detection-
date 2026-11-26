import os
import tempfile
import pytest

from services.repository_analysis_service import RepositoryAnalysisService


def test_detect_file_language():
    """Test language detection from file extensions."""
    assert RepositoryAnalysisService.detect_file_language("app/main.py") == "python"
    assert RepositoryAnalysisService.detect_file_language("src/index.js") == "javascript"
    assert RepositoryAnalysisService.detect_file_language("src/types.ts") == "typescript"
    assert RepositoryAnalysisService.detect_file_language("README.md") is None


def test_analyze_repository_multi_file():
    """Test analyzing a repository containing Python code, JavaScript, and manifest files."""
    with tempfile.TemporaryDirectory() as repo_dir:
        # Create a Python file with SQL injection vulnerability
        py_file = os.path.join(repo_dir, "database.py")
        with open(py_file, "w", encoding="utf-8") as f:
            f.write(
                "import sqlite3\n"
                "def get_user(user_id):\n"
                "    conn = sqlite3.connect('test.db')\n"
                "    cur = conn.cursor()\n"
                "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
                "    cur.execute(query)\n"
                "    return cur.fetchall()\n"
            )

        # Create a requirements.txt file
        req_file = os.path.join(repo_dir, "requirements.txt")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write("requests==2.19.0\nurllib3==1.24.1\n")

        # Create a directory to ignore (node_modules)
        nm_dir = os.path.join(repo_dir, "node_modules")
        os.makedirs(nm_dir, exist_ok=True)
        with open(os.path.join(nm_dir, "ignored.js"), "w", encoding="utf-8") as f:
            f.write("console.log('should be ignored');\n")

        progress_calls = []

        def on_progress(processed, total, count):
            progress_calls.append((processed, total, count))

        service = RepositoryAnalysisService()
        result = service.analyze_repository(
            repo_root=repo_dir,
            scan_id="scan-repo-test-01",
            progress_callback=on_progress,
        )

        assert result.scan_id == "scan-repo-test-01"
        assert result.scanned_files_count >= 1
        assert len(result.findings) >= 1
        assert "total" in result.findings_count
        assert any(f.get("cwe") in ["CWE-89", "CWE-79", "CWE-94"] or "SQL" in f.get("title", "") for f in result.findings)
        assert len(progress_calls) > 0


def test_repository_scan_service_persists_to_db(db_session, normal_user):
    """Verify RepositoryScanService persists Scan & canonical Finding rows without crashing."""
    from unittest.mock import patch
    from services.repository_scan_service import RepositoryScanService
    from db.models import Scan, Finding

    with tempfile.TemporaryDirectory() as fake_repo:
        with open(os.path.join(fake_repo, "vuln.py"), "w", encoding="utf-8") as f:
            f.write("import os\nos.system('ls ' + user_dir)\n")

        svc = RepositoryScanService(db=db_session)
        with patch.object(svc.github_repo_service, "resolve_ref_commit_sha", return_value="abcdef1234567890"), \
             patch.object(svc.downloader, "download_and_extract", return_value=(fake_repo, "abcdef1234567890")), \
             patch.object(svc.downloader, "cleanup", return_value=None):
            res = svc.execute_repository_scan(
                repository_url="https://github.com/acme/vuln-repo",
                branch="main",
                user_id=normal_user.id,
            )

        assert res["status"] == "COMPLETED"
        persisted_scan = db_session.query(Scan).filter(Scan.id == res["id"]).first()
        assert persisted_scan is not None
        assert persisted_scan.status == "COMPLETED"
        assert persisted_scan.user_id == normal_user.id
        persisted_findings = db_session.query(Finding).filter(Finding.scan_id == res["id"]).all()
        assert len(persisted_findings) >= 1
