from typing import Dict, Any
from fastapi import APIRouter

from schemas.common import ApiResponse
from services.health_service import health_service

router = APIRouter(prefix="/health", tags=["Diagnostics & System Health"])


@router.get("", response_model=ApiResponse[Dict[str, Any]])
def get_health_status():
    """Live diagnostic probe reporting PostgreSQL/SQLite, Redis, Celery, ML model, and OSV connectivity."""
    health_data = health_service.get_system_health()
    return ApiResponse(
        success=True,
        message="System health status retrieved.",
        data=health_data,
    )


@router.get("/metrics", response_model=ApiResponse[Dict[str, Any]])
def get_health_metrics():
    """Operational telemetry metrics for monitoring dashboards, queue length, and subsystem latency."""
    metrics_data = health_service.get_system_metrics()
    return ApiResponse(
        success=True,
        message="Operational metrics retrieved.",
        data=metrics_data,
    )
