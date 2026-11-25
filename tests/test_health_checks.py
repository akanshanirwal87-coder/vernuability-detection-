import pytest
from services.health_service import HealthService, health_service
from core.config import settings


def test_health_check_endpoint(client):
    """Test GET /health returns live system probe statuses."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "checks" in data
    assert "database" in data["checks"]
    assert "machineLearning" in data["checks"]
    assert "osvService" in data["checks"]
    assert "manageEngine" in data["checks"]

    # Database must be UP in normal execution
    assert data["checks"]["database"]["status"] == "UP"
    assert data["databaseConnected"] is True

    # ML model must be loaded
    assert data["mlModelLoaded"] is True
    assert data["checks"]["machineLearning"]["status"] == "UP"


def test_health_check_does_not_expose_secrets(client):
    """Verify that health check never leaks secret keys or password hashes."""
    res = client.get("/health")
    content = res.text

    assert settings.JWT_SECRET_KEY not in content
    assert settings.ADMIN_API_KEY not in content
    assert settings.ADMIN_PASSWORD_HASH not in content


def test_health_check_degraded_on_db_down(tmp_path):
    """Verify that if database connection fails, system reports unhealthy status."""
    bad_db_path = str(tmp_path / "nonexistent_dir" / "bad.db")
    service = HealthService(db_path=bad_db_path)

    health = service.get_system_health()
    assert health["status"] == "unhealthy"
    assert health["checks"]["database"]["status"] == "DOWN"
    assert health["databaseConnected"] is False
