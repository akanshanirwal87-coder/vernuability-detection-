import pytest
from core.security import verify_password


def test_registration_success(client):
    """Test user registration with valid parameters and Argon2id password hashing."""
    res = client.post(
        "/api/v1/auth/register",
        json={
            "name": "David Bowie",
            "email": "david.bowie@example.com",
            "password": "SuperSecretPassword123!",
            "role": "USER",
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["success"] is True
    assert "access_token" in body["data"]
    assert "refresh_token" in body["data"]
    assert body["data"]["user"]["email"] == "david.bowie@example.com"
    assert body["data"]["user"]["role"] == "USER"


def test_registration_duplicate_email(client, normal_user):
    """Test duplicate registration rejection with 409 Conflict."""
    res = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Alice Duplicate",
            "email": normal_user.email,
            "password": "AnotherPassword123!",
        },
    )
    assert res.status_code == 409
    body = res.json()
    assert body["success"] is False
    assert body["error_code"] == "RESOURCE_CONFLICT"


def test_login_success(client, normal_user):
    """Test login with correct credentials returns access and refresh tokens."""
    res = client.post(
        "/api/v1/auth/login",
        json={
            "email": normal_user.email,
            "password": "AliceSecurePassword2026!",
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert "access_token" in body["data"]
    assert "refresh_token" in body["data"]


def test_login_invalid_password(client, normal_user):
    """Test login failure with invalid password returns 401."""
    res = client.post(
        "/api/v1/auth/login",
        json={
            "email": normal_user.email,
            "password": "WrongPassword999!",
        },
    )
    assert res.status_code == 401
    body = res.json()
    assert body["success"] is False
    assert body["error_code"] == "AUTHENTICATION_FAILED"


def test_refresh_token_rotation(client, normal_user):
    """Test refresh token rotation: old refresh token is revoked, new tokens issued."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "email": normal_user.email,
            "password": "AliceSecurePassword2026!",
        },
    )
    first_refresh = login_res.json()["data"]["refresh_token"]

    # Use refresh token
    refresh_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first_refresh},
    )
    assert refresh_res.status_code == 200
    second_refresh = refresh_res.json()["data"]["refresh_token"]
    assert second_refresh != first_refresh

    # Re-using the first refresh token must fail because it was rotated/revoked
    reuse_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first_refresh},
    )
    assert reuse_res.status_code == 401


def test_logout_revokes_token(client, normal_user):
    """Test logout terminates session by revoking refresh token."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "email": normal_user.email,
            "password": "AliceSecurePassword2026!",
        },
    )
    refresh_tok = login_res.json()["data"]["refresh_token"]

    logout_res = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_tok},
    )
    assert logout_res.status_code == 200
    assert logout_res.json()["data"]["revoked"] is True

    # Refreshing with the revoked token must fail
    fail_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_tok},
    )
    assert fail_res.status_code == 401
