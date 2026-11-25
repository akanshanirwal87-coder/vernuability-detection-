import pytest


def test_get_current_user_profile(client, auth_headers, normal_user):
    """Test retrieving authenticated user profile."""
    res = client.get("/api/v1/auth/me", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["data"]["id"] == normal_user.id
    assert body["data"]["email"] == normal_user.email
    assert body["data"]["role"] == normal_user.role


def test_get_current_user_unauthenticated(client):
    """Test that accessing /api/v1/auth/me without token returns 401."""
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
