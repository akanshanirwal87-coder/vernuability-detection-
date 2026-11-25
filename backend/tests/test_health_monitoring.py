import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from services.health_service import health_service


def test_health_service_probes():
    """Test health service aggregate probe methods."""
    db_res = health_service.check_database()
    assert db_res["status"] in ["UP", "DOWN"]
    assert "latencyMs" in db_res

    ml_res = health_service.check_model_loading()
    assert ml_res["status"] in ["UP", "DEGRADED"]
    assert "modelName" in ml_res

    system_health = health_service.get_system_health()
    assert system_health["status"] in ["healthy", "degraded", "unhealthy"]
    assert "checks" in system_health
    assert "database" in system_health["checks"]
    assert "redis" in system_health["checks"]
    assert "celery" in system_health["checks"]


def test_health_endpoints(client: TestClient):
    """Test GET /health and GET /api/v1/health endpoints."""
    # Root /health
    resp1 = client.get("/health")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert "status" in data1
    assert "checks" in data1

    # API v1 /api/v1/health
    resp2 = client.get("/api/v1/health")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["success"] is True
    assert "data" in data2
    assert "status" in data2["data"]

    # Telemetry metrics endpoint /api/v1/health/metrics
    resp3 = client.get("/api/v1/health/metrics")
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["success"] is True
    assert "uptimeSeconds" in data3["data"]
    assert "databaseLatencyMs" in data3["data"]
