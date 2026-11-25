import time
import os
from typing import Optional, Dict, Any
import jwt
import requests
from core.config import settings
from core.logging_config import logger


class GitHubAuthError(Exception):
    """Raised when GitHub App or OAuth authentication fails."""
    pass


class GitHubAuth:
    """Manages GitHub App RS256 JWT generation and installation token caching."""

    def __init__(self):
        self._installation_token_cache: Dict[str, Dict[str, Any]] = {}

    def get_app_jwt(self) -> str:
        """Generate a short-lived (10 min) RS256 signed JWT for GitHub App authentication."""
        app_id = settings.GITHUB_APP_ID
        if not app_id:
            raise GitHubAuthError("GITHUB_APP_ID is not configured in environment.")

        private_key = self._load_private_key()
        if not private_key:
            raise GitHubAuthError("GitHub App private key is not configured or could not be loaded.")

        now = int(time.time())
        payload = {
            "iat": now - 60,  # 60s in the past to prevent clock drift issues
            "exp": now + (9 * 60),  # Valid for 9 minutes (max allowed by GitHub is 10 min)
            "iss": app_id,
        }

        try:
            token = jwt.encode(payload, private_key, algorithm="RS256")
            return token if isinstance(token, str) else token.decode("utf-8")
        except Exception as e:
            logger.error("Failed to sign GitHub App JWT: %s", str(e))
            raise GitHubAuthError(f"JWT signing failed: {str(e)}")

    def _load_private_key(self) -> Optional[str]:
        """Load private key from environment variable or key file path."""
        # Check inline PEM variable first
        if settings.GITHUB_APP_PRIVATE_KEY:
            key = settings.GITHUB_APP_PRIVATE_KEY.strip()
            # Handle potential escaped newlines from environment strings
            if "\\n" in key:
                key = key.replace("\\n", "\n")
            return key

        # Check key file path
        if settings.GITHUB_APP_PRIVATE_KEY_PATH:
            if os.path.isfile(settings.GITHUB_APP_PRIVATE_KEY_PATH):
                try:
                    with open(settings.GITHUB_APP_PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
                        return f.read().strip()
                except Exception as e:
                    logger.error("Error reading GITHUB_APP_PRIVATE_KEY_PATH: %s", str(e))
                    return None

        return None

    def get_installation_access_token(self, installation_id: str, force_refresh: bool = False) -> str:
        """Exchange App JWT for an installation access token, with in-memory caching."""
        now = time.time()
        cached = self._installation_token_cache.get(installation_id)

        # Return cached token if valid for at least 5 more minutes
        if cached and not force_refresh:
            if cached.get("expires_at_epoch", 0) - now > 300:
                return cached["token"]

        app_jwt = self.get_app_jwt()
        url = f"{settings.GITHUB_API_BASE_URL}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SecureCode-AI-Scanner",
        }

        try:
            resp = requests.post(url, headers=headers, timeout=10)
            if resp.status_code == 201:
                data = resp.json()
                token = data["token"]
                # GitHub installation tokens expire in 1 hour
                # Store epoch expiration (approx 3600 seconds)
                self._installation_token_cache[installation_id] = {
                    "token": token,
                    "expires_at_epoch": now + 3500,
                }
                return token
            elif resp.status_code == 404:
                raise GitHubAuthError(f"GitHub App installation {installation_id} not found.")
            else:
                logger.error("Failed to obtain installation token: %d %s", resp.status_code, resp.text)
                raise GitHubAuthError(f"GitHub API error ({resp.status_code}): {resp.text}")
        except requests.RequestException as e:
            logger.error("Network error requesting installation token: %s", str(e))
            raise GitHubAuthError(f"Connection to GitHub API failed: {str(e)}")

    def exchange_oauth_code(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """Exchange an OAuth authorization code for a user access token."""
        if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
            raise GitHubAuthError("GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET not configured.")

        url = "https://github.com/login/oauth/access_token"
        headers = {
            "Accept": "application/json",
            "User-Agent": "SecureCode-AI-Scanner",
        }
        payload = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
        }
        if redirect_uri:
            payload["redirect_uri"] = redirect_uri

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            data = resp.json()
            if "error" in data:
                raise GitHubAuthError(f"OAuth exchange error: {data.get('error_description', data['error'])}")
            return data
        except requests.RequestException as e:
            raise GitHubAuthError(f"OAuth network error: {str(e)}")


github_auth = GitHubAuth()
