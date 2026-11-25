from typing import Optional, Dict, Any, List
from integrations.github_client import GitHubClient, GitHubApiError
from core.logging_config import logger


class GitHubRepositoryService:
    """Manages repository metadata, branch selection, and authorization inspection."""

    def __init__(self, client: Optional[GitHubClient] = None):
        self.client = client or GitHubClient()

    def get_repo_details(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch repository metadata and visibility."""
        data = self.client.get_repository(owner, repo)
        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "full_name": data.get("full_name"),
            "owner": data.get("owner", {}).get("login"),
            "is_private": data.get("private", False),
            "default_branch": data.get("default_branch", "main"),
            "html_url": data.get("html_url"),
            "clone_url": data.get("clone_url"),
            "description": data.get("description"),
            "language": data.get("language"),
            "pushed_at": data.get("pushed_at"),
        }

    def resolve_ref_commit_sha(self, owner: str, repo: str, ref: Optional[str] = None) -> str:
        """Resolve a branch, tag, or ref to its exact 40-character commit SHA."""
        if not ref:
            repo_info = self.client.get_repository(owner, repo)
            ref = repo_info.get("default_branch", "main")

        # If already a 40-char commit SHA
        if len(ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in ref):
            return ref.lower()

        # Try branch
        try:
            branch_info = self.client.get_branch(owner, repo, ref)
            return branch_info["commit"]["sha"]
        except GitHubApiError:
            # Try direct commit reference
            commit_info = self.client.get_commit(owner, repo, ref)
            return commit_info["sha"]

    def list_branches(self, owner: str, repo: str) -> List[str]:
        """List available branch names in repository."""
        branches = self.client.list_branches(owner, repo)
        return [b["name"] for b in branches if "name" in b]
