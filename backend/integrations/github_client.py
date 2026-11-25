import time
from typing import Optional, Dict, Any, List, Iterator
import requests
from core.config import settings
from core.logging_config import logger


class GitHubApiError(Exception):
    """Raised when GitHub API calls encounter an error."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class GitHubRateLimitError(GitHubApiError):
    """Raised when GitHub API rate limit is exceeded."""
    def __init__(self, message: str, reset_epoch: Optional[int] = None):
        super().__init__(message, status_code=429)
        self.reset_epoch = reset_epoch


class GitHubClient:
    """Production client for interacting with the GitHub REST API v3."""

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = settings.GITHUB_API_BASE_URL

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SecureCode-AI-Scanner",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = kwargs.pop("headers", {})
        combined_headers = {**self._headers(), **headers}
        timeout = kwargs.pop("timeout", 15)

        try:
            resp = requests.request(method, url, headers=combined_headers, timeout=timeout, **kwargs)
        except requests.RequestException as e:
            logger.error("GitHub API request failed: %s %s -> %s", method, url, str(e))
            raise GitHubApiError(f"Network error connecting to GitHub: {str(e)}")

        # Check rate limits
        remaining = resp.headers.get("x-ratelimit-remaining")
        if remaining is not None and int(remaining) == 0:
            reset_time = int(resp.headers.get("x-ratelimit-reset", str(int(time.time()) + 60)))
            logger.warning("GitHub rate limit reached. Reset epoch: %d", reset_time)
            raise GitHubRateLimitError(
                f"GitHub API rate limit exceeded. Resets in {max(0, reset_time - int(time.time()))}s.",
                reset_epoch=reset_time
            )

        if resp.status_code == 404:
            raise GitHubApiError("Resource not found on GitHub.", status_code=404)
        elif resp.status_code == 401:
            raise GitHubApiError("GitHub authentication failed or token expired.", status_code=401)
        elif resp.status_code == 403:
            raise GitHubApiError(f"Access forbidden: {resp.text}", status_code=403)
        elif resp.status_code >= 400:
            raise GitHubApiError(f"GitHub API error ({resp.status_code}): {resp.text}", status_code=resp.status_code)

        return resp

    def get_authenticated_user(self) -> Dict[str, Any]:
        """Fetch profile of currently authenticated user."""
        return self._request("GET", "/user").json()

    def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch repository metadata."""
        return self._request("GET", f"/repos/{owner}/{repo}").json()

    def get_branch(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        """Fetch branch details including commit SHA."""
        return self._request("GET", f"/repos/{owner}/{repo}/branches/{branch}").json()

    def get_commit(self, owner: str, repo: str, commit_sha: str) -> Dict[str, Any]:
        """Fetch commit details."""
        return self._request("GET", f"/repos/{owner}/{repo}/commits/{commit_sha}").json()

    def list_branches(self, owner: str, repo: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """List repository branches."""
        return self._request("GET", f"/repos/{owner}/{repo}/branches", params={"per_page": per_page}).json()

    def download_zipball_stream(self, owner: str, repo: str, ref: str) -> requests.Response:
        """Stream repository zipball archive for extraction."""
        path = f"/repos/{owner}/{repo}/zipball/{ref}"
        return self._request("GET", path, stream=True, timeout=settings.REPO_DOWNLOAD_TIMEOUT_SECONDS)
