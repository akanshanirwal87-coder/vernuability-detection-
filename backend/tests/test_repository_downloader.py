import os
import io
import zipfile
import tempfile
import pytest
from unittest.mock import MagicMock

from integrations.repository_downloader import RepositoryDownloader, RepositoryDownloaderError
from integrations.github_client import GitHubClient


def create_zip_bytes(files_dict: dict) -> bytes:
    """Helper to create an in-memory zip file from a dictionary of filenames to bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files_dict.items():
            zf.writestr(fname, data)
    return buf.getvalue()


def test_download_and_extract_success():
    """Test safe extraction of a normal GitHub zipball archive."""
    files = {
        "acme-app-abc1234/main.py": b"print('hello world')\n",
        "acme-app-abc1234/requirements.txt": b"fastapi==0.110.0\n",
    }
    zip_data = create_zip_bytes(files)

    mock_client = MagicMock(spec=GitHubClient)
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Length": str(len(zip_data))}
    mock_resp.iter_content.return_value = [zip_data]
    mock_client.download_zipball_stream.return_value = mock_resp

    downloader = RepositoryDownloader(client=mock_client)
    target_dir = tempfile.mkdtemp(prefix="test_repo_extract_")

    try:
        root_dir, commit_sha = downloader.download_and_extract("acme", "app", "abc1234", destination_dir=target_dir)

        assert os.path.isdir(root_dir)
        assert os.path.exists(os.path.join(root_dir, "main.py"))
        assert os.path.exists(os.path.join(root_dir, "requirements.txt"))
        assert commit_sha == "abc1234"
    finally:
        downloader.cleanup(target_dir)


def test_download_and_extract_zip_slip_prevention():
    """Test detection and aborting on malicious Zip Slip archive containing path traversal."""
    malicious_files = {
        "safe_file.txt": b"safe",
        "../../etc/passwd": b"root:x:0:0:root:/root:/bin/bash",
    }
    zip_data = create_zip_bytes(malicious_files)

    mock_client = MagicMock(spec=GitHubClient)
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Length": str(len(zip_data))}
    mock_resp.iter_content.return_value = [zip_data]
    mock_client.download_zipball_stream.return_value = mock_resp

    downloader = RepositoryDownloader(client=mock_client)
    target_dir = tempfile.mkdtemp(prefix="test_zip_slip_")

    try:
        with pytest.raises(RepositoryDownloaderError, match="Zip Slip detected"):
            downloader.download_and_extract("attacker", "evil", "main", destination_dir=target_dir)
    finally:
        downloader.cleanup(target_dir)


def test_download_and_extract_corrupt_zip():
    """Test handling of corrupt or truncated zip data."""
    mock_client = MagicMock(spec=GitHubClient)
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Length": "10"}
    mock_resp.iter_content.return_value = [b"not_a_zip_file_header"]
    mock_client.download_zipball_stream.return_value = mock_resp

    downloader = RepositoryDownloader(client=mock_client)
    target_dir = tempfile.mkdtemp(prefix="test_corrupt_")

    try:
        with pytest.raises(RepositoryDownloaderError, match="Corrupt or invalid zip archive"):
            downloader.download_and_extract("acme", "app", "main", destination_dir=target_dir)
    finally:
        downloader.cleanup(target_dir)
