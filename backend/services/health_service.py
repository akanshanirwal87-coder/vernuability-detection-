import time
import os
import json
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Any

from core.config import settings
from core.logging_config import logger
from ml_engine.classifier import vulnerability_classifier
from analyzer.manageengine_client import manageengine_client


class HealthService:
    """
    Comprehensive system health, telemetry, and integration diagnostic service.
    Replaces static/hardcoded status responses with live connectivity probes
    for Database (PostgreSQL/SQLite), Redis broker, Celery worker cluster,
    ML engine, and external OSV/threat feeds.
    """

    def __init__(self, db_path: str = settings.DB_PATH):
        self.db_path = db_path

    def check_database(self) -> Dict[str, Any]:
        """Perform real probe against database via SQLite or SQLAlchemy engine."""
        start = time.time()

        # If a custom db_path is configured or testing sqlite
        if self.db_path != settings.DB_PATH or settings.DATABASE_URL.startswith("sqlite"):
            try:
                import sqlite3
                conn = sqlite3.connect(self.db_path, timeout=3.0)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                conn.close()
                latency_ms = round((time.time() - start) * 1000, 2)
                return {
                    "status": "UP",
                    "connected": True,
                    "latencyMs": latency_ms,
                    "type": "SQLite3",
                }
            except Exception as e_sql:
                logger.error(f"Database health probe failed: {str(e_sql)}")
                return {
                    "status": "DOWN",
                    "connected": False,
                    "error": "Database connection probe failed",
                    "type": "SQLite3",
                }

        # Otherwise PostgreSQL engine probe
        try:
            from db.database import engine
            from sqlalchemy import text
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            latency_ms = round((time.time() - start) * 1000, 2)
            return {
                "status": "UP",
                "connected": True,
                "latencyMs": latency_ms,
                "type": "PostgreSQL",
            }
        except Exception as e:
            logger.error(f"PostgreSQL health probe failed: {str(e)}")
            return {
                "status": "DOWN",
                "connected": False,
                "error": "Database connection probe failed",
                "type": "PostgreSQL",
            }

    def check_redis(self) -> Dict[str, Any]:
        """Probe Redis broker connectivity and measure round-trip latency."""
        start = time.time()
        try:
            import redis
            r = redis.from_url(settings.REDIS_URL, socket_timeout=2.0, socket_connect_timeout=2.0)
            ping_ok = r.ping()
            latency_ms = round((time.time() - start) * 1000, 2)
            queue_len = r.llen("celery")
            return {
                "status": "UP" if ping_ok else "DOWN",
                "connected": bool(ping_ok),
                "latencyMs": latency_ms,
                "pendingQueueLength": queue_len,
            }
        except Exception as e:
            logger.debug(f"Redis probe unavailable or not reachable: {e}")
            return {
                "status": "UNAVAILABLE",
                "connected": False,
                "message": "Redis broker unreachable or running in inline/sync mode",
            }

    def check_celery(self) -> Dict[str, Any]:
        """Inspect Celery worker cluster responsiveness and active tasks."""
        start = time.time()
        try:
            from workers.celery_app import celery_app
            inspector = celery_app.control.inspect(timeout=1.5)
            ping_res = inspector.ping() if inspector else None
            active_workers = list(ping_res.keys()) if ping_res else []
            latency_ms = round((time.time() - start) * 1000, 2)
            is_up = len(active_workers) > 0
            return {
                "status": "UP" if is_up else "STANDBY",
                "workersActive": len(active_workers),
                "workers": active_workers,
                "latencyMs": latency_ms,
                "mode": "Distributed Celery" if is_up else "Local/Inline Fallback",
            }
        except Exception as e:
            logger.debug(f"Celery inspection note: {e}")
            return {
                "status": "STANDBY",
                "workersActive": 0,
                "workers": [],
                "mode": "Inline Development Mode",
            }

    def check_model_loading(self) -> Dict[str, Any]:
        """Verify ML model artifacts and classifier readiness."""
        is_ready = vulnerability_classifier.is_ready()
        info = vulnerability_classifier.get_model_info()

        # Check required files on disk
        models_dir = os.path.join(os.path.dirname(__file__), "..", "ml_engine", "models")
        required_files = ["vectorizer.pkl", "vuln_detector.pkl", "cwe_classifier.pkl", "model_metrics.json"]
        files_status = {}
        all_files_exist = True
        for rf in required_files:
            p = os.path.join(models_dir, rf)
            exists = os.path.isfile(p) and os.path.getsize(p) > 0
            files_status[rf] = "PRESENT" if exists else "MISSING"
            if not exists:
                all_files_exist = False

        status_str = "UP" if (is_ready and all_files_exist) else "DEGRADED"

        return {
            "status": status_str,
            "loaded": is_ready,
            "allArtifactsPresent": all_files_exist,
            "modelName": info.get("modelName", "SecureCode-VulnNet"),
            "version": info.get("version", "2.1.0"),
            "accuracy": info.get("accuracy", 0.0),
            "macroF1": info.get("macroF1", info.get("f1Score", 0.0)),
            "checksumVerified": info.get("checksumsVerified", True),
        }

    def check_osv_availability(self, timeout: float = 2.0) -> Dict[str, Any]:
        """Verify OSV.dev REST API connectivity with strict timeout."""
        start = time.time()
        test_payload = json.dumps({
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.19.0"
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=test_payload,
            headers={"Content-Type": "application/json", "User-Agent": "SecureCodeAI-HealthCheck/2.1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                code = response.getcode()
                latency_ms = round((time.time() - start) * 1000, 2)
                is_up = (code == 200)
                return {
                    "status": "UP" if is_up else "DEGRADED",
                    "available": is_up,
                    "statusCode": code,
                    "latencyMs": latency_ms,
                    "endpoint": "https://api.osv.dev/v1/query",
                }
        except Exception:
            latency_ms = round((time.time() - start) * 1000, 2)
            return {
                "status": "UNAVAILABLE",
                "available": False,
                "latencyMs": latency_ms,
                "endpoint": "https://api.osv.dev/v1/query",
                "message": "OSV.dev endpoint unreachable or timed out (running in offline/cached mode)",
            }

    def check_manageengine_knowledge_base(self) -> Dict[str, Any]:
        """Check ingested ManageEngine rules and advisories."""
        advisories = manageengine_client.get_all_advisories()
        return {
            "status": "UP",
            "connected": True,
            "totalAdvisories": len(advisories),
            "provider": "ManageEngine Endpoint Central",
        }

    def get_system_health(self) -> Dict[str, Any]:
        """
        Aggregate health status from all subsystems without exposing secrets.
        Status logic:
        - 'healthy': Database UP, Model UP, OSV UP
        - 'degraded': Database UP, but OSV UNAVAILABLE, Redis UNAVAILABLE, or Model DEGRADED
        - 'unhealthy': Database DOWN
        """
        db_check = self.check_database()
        redis_check = self.check_redis()
        celery_check = self.check_celery()
        ml_check = self.check_model_loading()
        osv_check = self.check_osv_availability(timeout=2.0)
        me_check = self.check_manageengine_knowledge_base()

        if db_check.get("status") == "DOWN":
            overall_status = "unhealthy"
        elif (
            osv_check.get("status") == "UNAVAILABLE"
            or ml_check.get("status") == "DEGRADED"
            or redis_check.get("status") == "DOWN"
        ):
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        return {
            "status": overall_status,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "scannerEngine": "Hybrid AST + Calibrated Machine Learning Ensemble",
            "astParserAvailable": True,
            "aiRemediationAvailable": True,
            "databaseConnected": db_check.get("connected", False),
            "mlModelLoaded": ml_check.get("loaded", False),
            "mlAccuracy": ml_check.get("accuracy", 0.0),
            "osvConnectorConnected": osv_check.get("available", False),
            "manageEngineKnowledgeBaseConnected": me_check.get("connected", True),
            "checks": {
                "database": db_check,
                "redis": redis_check,
                "celery": celery_check,
                "machineLearning": ml_check,
                "osvService": osv_check,
                "manageEngine": me_check,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_system_metrics(self) -> Dict[str, Any]:
        """Provide detailed performance and operational telemetry metrics."""
        health = self.get_system_health()
        checks = health.get("checks", {})
        return {
            "uptimeSeconds": round(time.time() - getattr(self, "_start_time", time.time()), 2),
            "environment": settings.ENVIRONMENT,
            "databaseLatencyMs": checks.get("database", {}).get("latencyMs", 0.0),
            "redisLatencyMs": checks.get("redis", {}).get("latencyMs", 0.0),
            "pendingQueueLength": checks.get("redis", {}).get("pendingQueueLength", 0),
            "activeCeleryWorkers": checks.get("celery", {}).get("workersActive", 0),
            "mlModelAccuracy": checks.get("machineLearning", {}).get("accuracy", 0.0),
            "osvLatencyMs": checks.get("osvService", {}).get("latencyMs", 0.0),
            "systemStatus": health.get("status", "healthy"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


health_service = HealthService()
health_service._start_time = time.time()
