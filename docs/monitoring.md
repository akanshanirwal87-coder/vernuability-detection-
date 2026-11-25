# Application Monitoring & Telemetry

SecureCode AI provides live diagnostic probes and telemetry reporting to monitor subsystem health, broker availability, and analysis throughput.

---

## 1. Health & Diagnostic Endpoints

### 1.1 `GET /health` and `GET /api/v1/health`
Performs live connectivity and readiness checks across all core subsystems without exposing credentials or internal connection strings:

```json
{
  "status": "healthy",
  "version": "2.1.0",
  "environment": "production",
  "scannerEngine": "Hybrid AST + Calibrated Machine Learning Ensemble",
  "databaseConnected": true,
  "mlModelLoaded": true,
  "mlAccuracy": 0.941,
  "osvConnectorConnected": true,
  "checks": {
    "database": {
      "status": "UP",
      "connected": true,
      "latencyMs": 1.42,
      "type": "PostgreSQL"
    },
    "redis": {
      "status": "UP",
      "connected": true,
      "latencyMs": 0.85,
      "pendingQueueLength": 0
    },
    "celery": {
      "status": "UP",
      "workersActive": 4,
      "mode": "Distributed Celery"
    },
    "machineLearning": {
      "status": "UP",
      "loaded": true,
      "allArtifactsPresent": true,
      "modelName": "SecureCode-VulnNet",
      "accuracy": 0.941
    },
    "osvService": {
      "status": "UP",
      "available": true,
      "statusCode": 200,
      "latencyMs": 145.2
    }
  },
  "timestamp": "2026-03-01T12:00:00Z"
}
```

### 1.2 `GET /api/v1/health/metrics`
Exposes operational metrics suitable for Prometheus scrapers or operational dashboards:
- `uptimeSeconds`: Process uptime duration.
- `databaseLatencyMs`: Database round-trip ping time.
- `redisLatencyMs`: Redis broker round-trip ping time.
- `pendingQueueLength`: Current number of jobs awaiting worker pickup.
- `activeCeleryWorkers`: Count of live responsive Celery worker processes.
- `mlModelAccuracy`: Evaluated test-set accuracy of the loaded ML ensemble model.
- `osvLatencyMs`: Network response time for OSV.dev queries.

---

## 2. Structured JSON Logging

All backend and worker logging is structured in JSON format (`core/logging_config.py`):
```json
{
  "timestamp": "2026-03-01T12:00:00.123456+00:00",
  "level": "INFO",
  "logger": "securecode",
  "message": "Successfully enqueued scan task to Celery: job=job-12345678, scan=scan-repo-abcdef01"
}
```
Log output is stream-friendly for container log drivers (`fluentd`, `datadog`, `awslogs`, `json-file`).
