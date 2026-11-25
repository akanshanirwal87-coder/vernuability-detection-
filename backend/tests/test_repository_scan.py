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
        assert any(f.get("cwe_id") in ["CWE-89", "CWE-79", "CWE-94"] or "SQL" in f.get("title", "") for f in result.findings)
        assert len(progress_calls) > 0
