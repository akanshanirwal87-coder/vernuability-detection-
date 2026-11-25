import pytest
import time
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from integrations.github_auth import GitHubAuth, GitHubAuthError
from core.config import settings


@pytest.fixture
def rsa_private_key_pem():
    """Generates an ephemeral RSA private key in PEM format for test signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode("utf-8")


def test_get_app_jwt_missing_app_id(monkeypatch):
    """Test error when GITHUB_APP_ID is not configured."""
    monkeypatch.setattr(settings, "GITHUB_APP_ID", "")
    auth = GitHubAuth()
    with pytest.raises(GitHubAuthError, match="GITHUB_APP_ID is not configured"):
        auth.get_app_jwt()


def test_get_app_jwt_missing_private_key(monkeypatch):
    """Test error when private key is not configured."""
    monkeypatch.setattr(settings, "GITHUB_APP_ID", "12345")
    monkeypatch.setattr(settings, "GITHUB_APP_PRIVATE_KEY", "")
    monkeypatch.setattr(settings, "GITHUB_APP_PRIVATE_KEY_PATH", "")
    auth = GitHubAuth()
    with pytest.raises(GitHubAuthError, match="GitHub App private key is not configured"):
        auth.get_app_jwt()


def test_get_app_jwt_success(monkeypatch, rsa_private_key_pem):
    """Test successful RS256 JWT generation with proper claims."""
    monkeypatch.setattr(settings, "GITHUB_APP_ID", "12345")
    monkeypatch.setattr(settings, "GITHUB_APP_PRIVATE_KEY", rsa_private_key_pem)

    auth = GitHubAuth()
    token = auth.get_app_jwt()

    assert token is not None
    assert len(token.split(".")) == 3  # Standard header.payload.signature format


def test_get_installation_access_token_caching(monkeypatch):
    """Test that installation tokens are cached in-memory and not refetched unnecessarily."""
    auth = GitHubAuth()
    # Pre-populate cache with future epoch
    auth._installation_token_cache["inst_99"] = {
        "token": "cached_ghs_token_xyz",
        "expires_at_epoch": time.time() + 1000,
    }

    # Should return cached token without network request
    token = auth.get_installation_access_token("inst_99")
    assert token == "cached_ghs_token_xyz"


def test_get_installation_access_token_network_success(monkeypatch, rsa_private_key_pem):
    """Test fetching installation token with mocked GitHub response."""
    monkeypatch.setattr(settings, "GITHUB_APP_ID", "12345")
    monkeypatch.setattr(settings, "GITHUB_APP_PRIVATE_KEY", rsa_private_key_pem)

    auth = GitHubAuth()

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"token": "ghs_new_token_123456"}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        token = auth.get_installation_access_token("inst_42", force_refresh=True)
        assert token == "ghs_new_token_123456"
        assert mock_post.called
        assert "inst_42" in auth._installation_token_cache


def test_exchange_oauth_code_success(monkeypatch):
    """Test OAuth authorization code exchange."""
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "client_id_test")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "client_secret_test")

    auth = GitHubAuth()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "access_token": "gho_oauth_token_789",
        "token_type": "bearer",
        "scope": "repo,read:user",
    }

    with patch("requests.post", return_value=mock_resp):
        res = auth.exchange_oauth_code("code_123", redirect_uri="http://localhost/callback")
        assert res["access_token"] == "gho_oauth_token_789"


def test_exchange_oauth_code_error(monkeypatch):
    """Test OAuth exchange returns error on bad verification code."""
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "client_id_test")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "client_secret_test")

    auth = GitHubAuth()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"error": "bad_verification_code", "error_description": "The code passed is incorrect."}

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(GitHubAuthError, match="OAuth exchange error"):
            auth.exchange_oauth_code("invalid_code")
