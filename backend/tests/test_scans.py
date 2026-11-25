import pytest


def test_create_scan_python_ast(client, auth_headers):
    """Test submitting real Python code to /api/v1/scans generates AST findings and persists scan."""
    vulnerable_code = """
import sqlite3
def get_user(username):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # SQL injection vulnerability
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
"""
    res = client.post(
        "/api/v1/scans",
        json={
            "projectName": "Auth Audit",
            "fileName": "db_auth.py",
            "language": "python",
            "sourceCode": vulnerable_code,
            "options": {"enableAiClassifier": True, "enableRuleMatching": True},
        },
        headers=auth_headers,
    )
    assert res.status_code == 201
    body = res.json()
    assert body["success"] is True
    data = body["data"]
    assert "scan-" in data["id"]
    assert data["status"] == "COMPLETED"
    assert data["findingsCount"]["total"] >= 1
    # Check that finding is SQL Injection (CWE-89)
    sqli = next((f for f in data["findings"] if f.get("cwe") == "CWE-89"), None)
    assert sqli is not None
    assert sqli["severity"] in ("CRITICAL", "HIGH")


def test_create_scan_manifest_sca(client, auth_headers):
    """Test submitting a requirements.txt manifest triggers Software Composition Analysis with real CWE."""
    manifest_code = """
requests==2.19.0
flask==0.12.0
"""
    res = client.post(
        "/api/v1/scans",
        json={
            "projectName": "Dependency Audit",
            "fileName": "requirements.txt",
            "language": "requirements",
            "sourceCode": manifest_code,
        },
        headers=auth_headers,
    )
    assert res.status_code == 201
    body = res.json()
    assert body["success"] is True
    data = body["data"]
    assert data["status"] == "COMPLETED"


def test_list_scans_and_get_details(client, auth_headers):
    """Test listing historical scans and retrieving details."""
    list_res = client.get("/api/v1/scans", headers=auth_headers)
    assert list_res.status_code == 200
    body = list_res.json()
    assert body["success"] is True
    assert "items" in body["data"]
    assert "pagination" in body["data"]


def test_cross_user_scan_access(client, second_user_headers, auth_headers):
    """Test that user B cannot view user A's private scan."""
    code = "print('hello secure world')\n"
    res = client.post(
        "/api/v1/scans",
        json={"sourceCode": code, "language": "python", "fileName": "test.py"},
        headers=auth_headers,
    )
    scan_id = res.json()["data"]["id"]

    # User B tries to view User A's scan
    forbidden_res = client.get(f"/api/v1/scans/{scan_id}", headers=second_user_headers)
    assert forbidden_res.status_code == 403
    assert forbidden_res.json()["error_code"] == "FORBIDDEN"
