import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple
from core.config import settings


class RepositoryValidationError(Exception):
    """Raised when repository URL or metadata fails security validation."""
    pass


class RepositoryValidator:
    """Validates repository URLs, prevents SSRF, and sanitizes identifiers."""

    NAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{1,100}$")

    @classmethod
    def validate_url(cls, raw_url: str) -> Tuple[str, str]:
        """Validate repository URL structure and extract (owner, repo). Prevents SSRF."""
        if not raw_url or not isinstance(raw_url, str):
            raise RepositoryValidationError("Repository URL must be a non-empty string.")

        raw_url = raw_url.strip()
        parsed = urlparse(raw_url)

        if parsed.scheme.lower() not in ("https", "http"):
            raise RepositoryValidationError(f"Invalid scheme '{parsed.scheme}'. Only HTTPS is permitted.")

        # In production, require HTTPS strictly
        if settings.ENVIRONMENT != "development" and parsed.scheme.lower() != "https":
            raise RepositoryValidationError("In production, repository URLs must use HTTPS.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise RepositoryValidationError("Invalid repository URL: Missing hostname.")

        # Check allowed hosts
        allowed_hosts = settings.ALLOWED_GITHUB_HOSTS
        if hostname not in allowed_hosts and not hostname.endswith(".github.com"):
            raise RepositoryValidationError(
                f"Host '{hostname}' is not permitted. Only GitHub repositories are supported ({', '.join(allowed_hosts)})."
            )

        # SSRF Prevention: Resolve hostname and check IP boundaries
        cls._verify_ip_boundaries(hostname)

        # Path parsing: /owner/repo or /owner/repo.git
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(path_parts) < 2:
            raise RepositoryValidationError("URL path must contain owner and repository name (e.g., /owner/repo).")

        owner = path_parts[0]
        repo = path_parts[1]

        if repo.endswith(".git"):
            repo = repo[:-4]

        cls.validate_identifier(owner, "owner")
        cls.validate_identifier(repo, "repository")

        return owner, repo

    @classmethod
    def validate_branch(cls, branch: str) -> str:
        """Sanitize branch or ref name to prevent directory traversal or command injection."""
        if not branch or not isinstance(branch, str):
            raise RepositoryValidationError("Branch name must be a non-empty string.")
        branch = branch.strip()
        if ".." in branch:
            raise RepositoryValidationError("Directory traversal detected in branch name: '..'")
        if not re.match(r"^[a-zA-Z0-9_./-]{1,100}$", branch):
            raise RepositoryValidationError(f"Invalid character in branch name: '{branch}'")
        return branch

    @classmethod
    def validate_identifier(cls, val: str, label: str = "identifier") -> None:
        """Validate owner or repo name against strict character set to prevent injection."""
        if not val or not cls.NAME_REGEX.match(val):
            raise RepositoryValidationError(
                f"Invalid {label} '{val}'. Must match ^[a-zA-Z0-9_.-]{{1,100}}$ without traversal sequences."
            )
        if ".." in val:
            raise RepositoryValidationError(f"Path traversal detected in {label}: '..'")

    @classmethod
    def _verify_ip_boundaries(cls, hostname: str) -> None:
        """Resolve hostname to verify it does not point to internal/private IP ranges (SSRF prevention)."""
        # If hostname is already an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise RepositoryValidationError(
                    f"SSRF prevention triggered: Hostname '{hostname}' is a restricted internal IP."
                )
            return
        except ValueError:
            pass

        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            # In offline test environments where DNS is unavailable, allow whitelisted github domains
            if hostname in ("github.com", "api.github.com", "raw.githubusercontent.com"):
                return
            raise RepositoryValidationError(f"Could not resolve hostname '{hostname}': {str(e)}")

        for info in addr_info:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            if (
                ip.is_loopback  # 127.0.0.0/8, ::1
                or ip.is_private  # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                or ip.is_link_local  # 169.254.0.0/16
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise RepositoryValidationError(
                    f"SSRF prevention triggered: Hostname '{hostname}' resolves to restricted internal IP '{ip_str}'."
                )
