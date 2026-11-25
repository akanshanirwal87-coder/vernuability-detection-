import hmac
import hashlib
import json
import pytest

from integrations.github_webhooks import GitHubWebhookHandler


def test_verify_signature_valid():
    """Test valid HMAC-SHA256 signature verification."""
    secret = "super_secure_webhook_secret_123"
    payload = b'{"action": "ping"}'
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    assert GitHubWebhookHandler.verify_signature(payload, sig, secret=secret) is True


def test_verify_signature_tampered():
    """Test rejection when payload is tampered or signature doesn't match."""
    secret = "super_secure_webhook_secret_123"
    payload = b'{"action": "ping"}'
    tampered_sig = "sha256=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

    assert GitHubWebhookHandler.verify_signature(payload, tampered_sig, secret=secret) is False


def test_verify_signature_missing_header():
    """Test rejection when signature header is missing or empty."""
    secret = "super_secure_webhook_secret_123"
    assert GitHubWebhookHandler.verify_signature(b'{}', None, secret=secret) is False
    assert GitHubWebhookHandler.verify_signature(b'{}', "", secret=secret) is False


def test_parse_push_event():
    """Test parsing a valid push webhook event."""
    payload = {
        "ref": "refs/heads/main",
        "after": "aabbccddeeff00112233445566778899aabbccdd",
        "repository": {
            "name": "backend-core",
            "html_url": "https://github.com/acme/backend-core",
            "private": True,
            "owner": {"login": "acme"},
        },
        "sender": {"login": "alice-dev"},
        "installation": {"id": 1234567},
    }

    parsed = GitHubWebhookHandler.parse_event("push", payload)
    assert parsed is not None
    assert parsed.event_type == "push"
    assert parsed.repository_name == "backend-core"
    assert parsed.repository_owner == "acme"
    assert parsed.commit_sha == "aabbccddeeff00112233445566778899aabbccdd"
    assert parsed.is_private is True
    assert parsed.installation_id == "1234567"


def test_parse_push_event_branch_deletion():
    """Test branch deletion events (all zeros SHA) are skipped."""
    payload = {
        "ref": "refs/heads/feature-old",
        "after": "0000000000000000000000000000000000000000",
        "repository": {
            "name": "backend-core",
            "owner": {"login": "acme"},
        },
    }
    assert GitHubWebhookHandler.parse_event("push", payload) is None


def test_parse_pull_request_event():
    """Test parsing pull_request opened event."""
    payload = {
        "action": "opened",
        "pull_request": {
            "head": {
                "ref": "patch-1",
                "sha": "112233445566778899aabbccddeeff0011223344",
            }
        },
        "repository": {
            "name": "backend-core",
            "html_url": "https://github.com/acme/backend-core",
            "private": False,
            "owner": {"login": "acme"},
        },
        "sender": {"login": "bob-contributor"},
    }

    parsed = GitHubWebhookHandler.parse_event("pull_request", payload)
    assert parsed is not None
    assert parsed.event_type == "pull_request"
    assert parsed.action == "opened"
    assert parsed.commit_sha == "112233445566778899aabbccddeeff0011223344"
