import pytest
from core.config import settings
from core.security import sanitize_filename, validate_upload, hash_password, verify_password


def test_cors_restriction(client):
    """Test that CORS restricts unconfigured origins and accepts allowed origins."""
    # Test allowed origin
    res = client.options(
        "/api/scans",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert res.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # Test unapproved origin
    res_unapproved = client.options(
        "/api/scans",
        headers={
            "Origin": "http://evil-attacker.com",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert res_unapproved.headers.get("access-control-allow-origin") != "http://evil-attacker.com"


def test_upload_requires_authentication(client):
    """Test that /api/scans/upload and /api/scans reject unauthenticated access."""
    valid_code = "import os\nprint('hello world')\n"
    res = client.post(
        "/api/scans/upload",
        data={"projectName": "Test Project", "language": "python"},
        files={"file": ("test_script.py", valid_code.encode("utf-8"), "text/plain")}
    )
    assert res.status_code == 401
    assert client.get("/api/scans").status_code == 401


def test_upload_valid_python_file(client, developer_headers):
    """Test uploading a valid Python source file when authenticated."""
    valid_code = "import os\nprint('hello world')\n"
    res = client.post(
        "/api/scans/upload",
        data={"projectName": "Test Project", "language": "python"},
        files={"file": ("test_script.py", valid_code.encode("utf-8"), "text/plain")},
        headers=developer_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["fileName"] == "test_script.py"


def test_upload_path_traversal_rejection(client, developer_headers):
    """Test that path traversal attempts in uploaded filenames are rejected with 400."""
    valid_code = "import os\n"
    # Attempt directory traversal
    res = client.post(
        "/api/scans/upload",
        data={"projectName": "Test Project", "language": "python"},
        files={"file": ("../../etc/passwd.py", valid_code.encode("utf-8"), "text/plain")},
        headers=developer_headers,
    )
    assert res.status_code == 400
    assert "Path traversal" in res.json()["detail"]


def test_upload_disallowed_extension(client, developer_headers):
    """Test that unauthorized executable extensions are rejected."""
    bad_content = b"echo 'malicious script'"
    res = client.post(
        "/api/scans/upload",
        data={"projectName": "Test Project", "language": "python"},
        files={"file": ("exploit.sh", bad_content, "text/plain")},
        headers=developer_headers,
    )
    assert res.status_code == 400
    assert "extension" in res.json()["detail"].lower()


def test_upload_oversized_file(client, developer_headers):
    """Test that files exceeding MAX_UPLOAD_SIZE_BYTES are rejected."""
    # 5MB + 10 bytes
    large_content = b"A" * (settings.MAX_UPLOAD_SIZE_BYTES + 10)
    res = client.post(
        "/api/scans/upload",
        data={"projectName": "Test Project", "language": "python"},
        files={"file": ("huge_file.py", large_content, "text/plain")},
        headers=developer_headers,
    )
    assert res.status_code == 400
    assert "exceeds" in res.json()["detail"].lower()


def test_uploaded_code_is_never_executed(client, developer_headers):
    """Verify that uploading dangerous code with system exit is analyzed statically, never executed."""
    hostile_code = """
import sys
# If executed, this would immediately terminate the server process
sys.exit(99)
"""
    res = client.post(
        "/api/scans/upload",
        data={"projectName": "Hostile Test", "language": "python"},
        files={"file": ("exit_test.py", hostile_code.encode("utf-8"), "text/plain")},
        headers=developer_headers,
    )
    # Server did not terminate; scan completed successfully
    assert res.status_code == 200
    assert res.json()["status"] == "COMPLETED"


def test_hardcoded_developer_backdoor_removed(client):
    """Verify the hardcoded developer account credential in legacy /api/auth/login is disabled."""
    res = client.post(
        "/api/auth/login",
        json={"username": "developer", "password": "DeveloperSecure2026!"},
    )
    assert res.status_code == 401


def test_auth_login_admin_success(client):
    """Test admin login with valid credentials."""
    res = client.post(
        "/api/auth/login",
        json={"username": settings.ADMIN_USERNAME, "password": "AdminSecure2026!"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"


def test_auth_login_invalid_password(client):
    """Test login failure with invalid password."""
    res = client.post(
        "/api/auth/login",
        json={"username": settings.ADMIN_USERNAME, "password": "WrongPassword123!"}
    )
    assert res.status_code == 401


def test_retrain_unauthorized_without_token(client):
    """Test that /api/ml/retrain rejects unauthenticated requests with 401."""
    res = client.post("/api/ml/retrain")
    assert res.status_code == 401


def test_retrain_forbidden_for_developer_role(client, developer_headers):
    """Test that non-admin authenticated users receive 403 Forbidden on retrain."""
    res = client.post("/api/ml/retrain", headers=developer_headers)
    assert res.status_code == 403
    assert "Administrative privileges required" in res.json()["detail"]


def test_retrain_authorized_with_admin_jwt(client, admin_headers):
    """Test that admin with valid JWT can access retraining."""
    # Test that route accepts admin credentials
    res = client.post("/api/ml/retrain", headers=admin_headers)
    assert res.status_code == 200
    assert "metrics" in res.json()


def test_retrain_authorized_with_api_key(client, admin_api_key_headers):
    """Test that admin with valid X-API-Key can access retraining."""
    res = client.post("/api/ml/retrain", headers=admin_api_key_headers)
    assert res.status_code == 200
    assert res.json()["triggeredBy"] == settings.ADMIN_USERNAME
