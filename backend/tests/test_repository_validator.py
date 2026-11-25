import pytest
from integrations.repository_validator import RepositoryValidator, RepositoryValidationError


def test_validate_url_valid_https():
    """Test valid GitHub repository URLs."""
    owner, repo = RepositoryValidator.validate_url("https://github.com/torvalds/linux")
    assert owner == "torvalds"
    assert repo == "linux"

    owner2, repo2 = RepositoryValidator.validate_url("https://github.com/my-org/my-project.git")
    assert owner2 == "my-org"
    assert repo2 == "my-project"


def test_validate_url_rejects_non_https():
    """Test non-HTTPS schemes are rejected."""
    with pytest.raises(RepositoryValidationError, match="Only HTTPS is permitted"):
        RepositoryValidator.validate_url("git@github.com:owner/repo.git")

    with pytest.raises(RepositoryValidationError, match="Only HTTPS is permitted"):
        RepositoryValidator.validate_url("ssh://git@github.com/owner/repo")

    with pytest.raises(RepositoryValidationError, match="Only HTTPS is permitted"):
        RepositoryValidator.validate_url("ftp://github.com/owner/repo")


def test_validate_url_rejects_unapproved_hosts():
    """Test unknown or untrusted hostnames are rejected."""
    with pytest.raises(RepositoryValidationError, match="Host 'evil.com' is not permitted"):
        RepositoryValidator.validate_url("https://evil.com/owner/repo")

    with pytest.raises(RepositoryValidationError, match="Host 'attacker.org' is not permitted"):
        RepositoryValidator.validate_url("https://attacker.org/owner/repo")


def test_validate_url_ssrf_protection_private_ip():
    """Test that URLs targeting private IP addresses (SSRF) are blocked."""
    with pytest.raises(RepositoryValidationError, match="Host '127.0.0.1' is not permitted"):
        RepositoryValidator.validate_url("https://127.0.0.1/owner/repo")

    with pytest.raises(RepositoryValidationError, match="Host '169.254.169.254' is not permitted"):
        RepositoryValidator.validate_url("https://169.254.169.254/latest/meta-data")


def test_validate_url_invalid_paths():
    """Test malformed URL paths."""
    with pytest.raises(RepositoryValidationError, match="URL path must contain"):
        RepositoryValidator.validate_url("https://github.com/")

    with pytest.raises(RepositoryValidationError, match="URL path must contain"):
        RepositoryValidator.validate_url("https://github.com/onlyowner")


def test_validate_branch_valid():
    """Test valid branch names."""
    assert RepositoryValidator.validate_branch("main") == "main"
    assert RepositoryValidator.validate_branch("feature/new-scanner-v2") == "feature/new-scanner-v2"
    assert RepositoryValidator.validate_branch("fix/issue_123") == "fix/issue_123"


def test_validate_branch_malicious():
    """Test branch names containing command injection or directory traversal characters."""
    with pytest.raises(RepositoryValidationError, match="Directory traversal"):
        RepositoryValidator.validate_branch("../main")

    with pytest.raises(RepositoryValidationError, match="Invalid character"):
        RepositoryValidator.validate_branch("main;rm -rf /")

    with pytest.raises(RepositoryValidationError, match="Invalid character"):
        RepositoryValidator.validate_branch("feature|cat /etc/passwd")
