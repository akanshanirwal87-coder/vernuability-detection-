import pytest


def test_standard_success_response_envelope(client, auth_headers):
    """Verify standard success response format: { success, message, data }."""
    res = client.get("/api/v1/projects", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert "success" in body
    assert body["success"] is True
    assert "message" in body
    assert "data" in body
    assert "items" in body["data"]
    assert "pagination" in body["data"]


def test_standard_not_found_response_envelope(client, auth_headers):
    """Verify standard error format on 404: { success: false, message, error_code: 'NOT_FOUND' }."""
    res = client.get("/api/v1/projects/nonexistent-project-999", headers=auth_headers)
    assert res.status_code == 404
    body = res.json()
    assert body["success"] is False
    assert body["error_code"] == "NOT_FOUND"
    assert "not found" in body["message"].lower()


def test_standard_validation_error_envelope(client):
    """Verify standard validation error format on 422: { success: false, message, error_code: 'VALIDATION_ERROR' }."""
    # Invalid email without @ domain
    res = client.post(
        "/api/v1/auth/register",
        json={"name": "A", "email": "invalid-email-no-domain", "password": "123"},
    )
    assert res.status_code == 422
    body = res.json()
    assert body["success"] is False
    assert body["error_code"] == "VALIDATION_ERROR"
