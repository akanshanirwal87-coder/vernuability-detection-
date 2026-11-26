import time
from urllib.parse import urlparse, urljoin
from typing import Optional, Dict, Any, List
import requests
from core.config import settings
from core.logging_config import logger
from integrations.repository_validator import RepositoryValidator, RepositoryValidationError


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

    ALLOWED_REDIRECT_HOSTS = {"github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com"}

    def _validate_redirect_url(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme.lower() != "https" or not hostname:
            raise GitHubApiError("Blocked unsafe non-HTTPS redirect from GitHub endpoint.", status_code=400)
        allowed = set(settings.ALLOWED_GITHUB_HOSTS) | self.ALLOWED_REDIRECT_HOSTS
        if hostname not in allowed:
            raise GitHubApiError(f"Blocked redirect to untrusted host '{hostname}'.", status_code=400)
        try:
            RepositoryValidator._verify_ip_boundaries(hostname)
        except RepositoryValidationError as exc:
            raise GitHubApiError(str(exc), status_code=400)
        return target_url

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = kwargs.pop("headers", {})
        combined_headers = {**self._headers(), **headers}
        timeout = kwargs.pop("timeout", 15)
        kwargs.pop("allow_redirects", None)

        current_url = url
        current_headers = dict(combined_headers)
        resp: Optional[requests.Response] = None

        try:
            for _ in range(5):
                resp = requests.request(
                    method,
                    current_url,
                    headers=current_headers,
                    timeout=timeout,
                    allow_redirects=False,
                    **kwargs,
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    resp.close()
                    if not location:
                        raise GitHubApiError("GitHub returned redirect without Location header.", status_code=502)
                    next_url = urljoin(current_url, location)
                    self._validate_redirect_url(next_url)
                    # Strip bearer authorization header when redirecting to external CDN host
                    if urlparse(next_url).hostname != urlparse(current_url).hostname:
                        current_headers.pop("Authorization", None)
                    current_url = next_url
                    continue
                break
            else:
                raise GitHubApiError("Too many redirects from GitHub API.", status_code=502)
        except GitHubApiError:
            raise
        except requests.RequestException as e:
            logger.error("GitHub API request failed: %s %s -> %s", method, url, str(e))
            raise GitHubApiError("Network error connecting to GitHub API.")

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
            logger.warning("GitHub API returned 403 for %s", current_url)
            raise GitHubApiError("Access forbidden by GitHub API.", status_code=403)
        elif resp.status_code >= 400:
            logger.warning("GitHub API error %d for %s", resp.status_code, current_url)
            raise GitHubApiError(f"GitHub API error ({resp.status_code}).", status_code=resp.status_code)

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
