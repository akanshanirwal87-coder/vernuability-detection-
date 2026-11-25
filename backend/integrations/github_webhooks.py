import hmac
import hashlib
from typing import Optional, Dict, Any
from pydantic import BaseModel
from core.config import settings
from core.logging_config import logger


class WebhookPayload(BaseModel):
    event_type: str
    repository_owner: str
    repository_name: str
    repository_url: str
    is_private: bool
    ref: str
    commit_sha: str
    sender: str
    installation_id: Optional[str] = None
    action: Optional[str] = None


class GitHubWebhookHandler:
    """Verifies HMAC SHA-256 signatures and processes GitHub webhook events."""

    @staticmethod
    def verify_signature(payload_bytes: bytes, signature_header: Optional[str], secret: Optional[str] = None) -> bool:
        """Verify the GitHub X-Hub-Signature-256 header using timing-safe comparison."""
        active_secret = secret or settings.GITHUB_WEBHOOK_SECRET
        if not active_secret:
            logger.warning("GITHUB_WEBHOOK_SECRET is not configured; rejecting webhook.")
            return False

        if not signature_header or not signature_header.startswith("sha256="):
            return False

        expected_sig = "sha256=" + hmac.new(
            active_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, signature_header)

    @staticmethod
    def parse_event(event_type: str, payload: Dict[str, Any]) -> Optional[WebhookPayload]:
        """Parse supported push and pull_request webhook events."""
        repo_data = payload.get("repository", {})
        if not repo_data:
            return None

        owner = repo_data.get("owner", {}).get("login") or repo_data.get("owner", {}).get("name", "")
        repo_name = repo_data.get("name", "")
        repo_url = repo_data.get("html_url", "")
        is_private = repo_data.get("private", False)
        sender = payload.get("sender", {}).get("login", "unknown")
        installation_id = str(payload.get("installation", {}).get("id")) if payload.get("installation") else None

        if event_type == "push":
            ref = payload.get("ref", "refs/heads/main")
            commit_sha = payload.get("after") or (payload.get("head_commit", {}) or {}).get("id", "")
            if not commit_sha or commit_sha == "0000000000000000000000000000000000000000":
                return None  # Branch deletion

            return WebhookPayload(
                event_type="push",
                repository_owner=owner,
                repository_name=repo_name,
                repository_url=repo_url,
                is_private=is_private,
                ref=ref,
                commit_sha=commit_sha,
                sender=sender,
                installation_id=installation_id,
            )

        elif event_type == "pull_request":
            action = payload.get("action")
            if action not in ("opened", "synchronize", "reopened"):
                return None

            pr = payload.get("pull_request", {})
            commit_sha = pr.get("head", {}).get("sha", "")
            ref = pr.get("head", {}).get("ref", "")

            return WebhookPayload(
                event_type="pull_request",
                repository_owner=owner,
                repository_name=repo_name,
                repository_url=repo_url,
                is_private=is_private,
                ref=ref,
                commit_sha=commit_sha,
                sender=sender,
                installation_id=installation_id,
                action=action,
            )

        return None
