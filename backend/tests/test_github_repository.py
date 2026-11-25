import pytest
from unittest.mock import MagicMock
from integrations.github_repository import GitHubRepositoryService
from integrations.github_client import GitHubClient, GitHubApiError


def test_get_repo_details_success():
    """Test parsing and normalising repository details from GitHub API."""
    mock_client = MagicMock(spec=GitHubClient)
    mock_client.get_repository.return_value = {
        "id": 987654,
        "name": "secure-app",
        "full_name": "acme/secure-app",
        "owner": {"login": "acme"},
        "private": False,
        "default_branch": "main",
        "html_url": "https://github.com/acme/secure-app",
        "clone_url": "https://github.com/acme/secure-app.git",
        "description": "Production security service",
        "language": "Python",
        "pushed_at": "2026-03-01T12:00:00Z",
    }

    service = GitHubRepositoryService(client=mock_client)
    details = service.get_repo_details("acme", "secure-app")

    assert details["name"] == "secure-app"
    assert details["owner"] == "acme"
    assert details["is_private"] is False
    assert details["default_branch"] == "main"
    assert details["language"] == "Python"


def test_resolve_ref_commit_sha_already_sha():
    """Test that a 40-character SHA ref is returned directly without API call."""
    mock_client = MagicMock(spec=GitHubClient)
    service = GitHubRepositoryService(client=mock_client)

    sha = "0123456789abcdef0123456789abcdef01234567"
    resolved = service.resolve_ref_commit_sha("acme", "secure-app", ref=sha)

    assert resolved == sha
    assert not mock_client.get_branch.called


def test_resolve_ref_commit_sha_from_branch():
    """Test resolving a branch name to its latest commit SHA."""
    mock_client = MagicMock(spec=GitHubClient)
    mock_client.get_branch.return_value = {
        "name": "develop",
        "commit": {"sha": "aabbccddeeff00112233445566778899aabbccdd"},
    }

    service = GitHubRepositoryService(client=mock_client)
    resolved = service.resolve_ref_commit_sha("acme", "secure-app", ref="develop")

    assert resolved == "aabbccddeeff00112233445566778899aabbccdd"
    mock_client.get_branch.assert_called_once_with("acme", "secure-app", "develop")


def test_list_branches():
    """Test listing repository branches."""
    mock_client = MagicMock(spec=GitHubClient)
    mock_client.list_branches.return_value = [
        {"name": "main", "commit": {"sha": "sha_main"}},
        {"name": "feature/auth", "commit": {"sha": "sha_feature"}},
    ]

    service = GitHubRepositoryService(client=mock_client)
    branches = service.list_branches("acme", "secure-app")

    assert len(branches) == 2
    assert branches[0] == "main"
    assert branches[1] == "feature/auth"
