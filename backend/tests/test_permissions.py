import pytest
from core.permissions import require_admin
from core.exceptions import AuthorizationException
from fastapi import HTTPException


def test_require_admin_allows_admin(admin_user):
    """Test require_admin allows ADMIN role."""
    user_dict = {"id": admin_user.id, "role": "ADMIN", "username": admin_user.name}
    result = require_admin(user=user_dict)
    assert result["role"] == "ADMIN"


def test_require_admin_rejects_user(normal_user):
    """Test require_admin raises 403 Forbidden for standard user."""
    user_dict = {"id": normal_user.id, "role": "USER", "username": normal_user.name}
    with pytest.raises(HTTPException) as exc_info:
        require_admin(user=user_dict)
    assert exc_info.value.status_code == 403


def test_api_key_admin_access(client):
    """Test that providing a valid X-API-Key grants administrative retraining access."""
    res = client.post("/api/ml/retrain", headers={"X-API-Key": "sec-admin-phase1-production-token-9f82d1c"})
    assert res.status_code == 200
    assert "metrics" in res.json()
