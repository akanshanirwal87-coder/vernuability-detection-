# Background Processing with Celery & Redis

SecureCode AI executes long-running repository vulnerability scans asynchronously using Celery and Redis.

---

## 1. Architecture Overview

```mermaid
flowchart LR
    A["Frontend / API Client"] -->|POST /api/v1/github/scan| B["FastAPI Backend"]
    B -->|Check In-flight Scans| C["Database (PostgreSQL)"]
    B -->|Enqueue Job| D["Redis Broker (redis://)"]
    B -->>|202 Accepted {jobId}| A
    D --> E["Celery Worker Cluster"]
    E -->|Download & Analyze| F["Repository Source"]
    E -->|Update Progress & Status| C
    A -->|GET /api/v1/github/jobs/{id}| B
    B -->|Query ScanJob & Redis| A
```

---

## 2. Scan Job States & Lifecycle

A background scan transitions through the following well-defined states:

| State | Description |
| :--- | :--- |
| **`QUEUED`** | Job entity recorded in database and submitted to the Redis queue. |
| **`RUNNING`** | Worker has picked up the job, streaming archive and executing analyzers. |
| **`COMPLETED`** | Scan finished successfully; findings, metrics, and risk report persisted. |
| **`FAILED`** | Scan encountered an unrecoverable error or timed out; failure message recorded. |
| **`CANCELLED`** | User explicitly cancelled the job via the API or frontend UI. |

---

## 3. Idempotency & Concurrency Control

To prevent denial of service and redundant resource consumption, `ScanQueueService` implements strict idempotency:
- Before enqueueing, the service queries active scans for the requested repository URL in states `PENDING`, `QUEUED`, or `RUNNING`.
- If an active scan exists, the existing `job_id` is returned with `isDuplicate: true` rather than spawning duplicate work.
- Callers can pass `force=True` to explicitly bypass idempotency and launch a fresh parallel scan.

---

## 4. Resilience, Timeouts & Automated Cleanup

1. **Task Timeouts**:
   - `CELERY_TASK_TIME_LIMIT`: 600 seconds (hard abort).
   - `CELERY_TASK_SOFT_TIME_LIMIT`: 540 seconds (graceful catch to persist timeout error message).
2. **Transient Error Retries**:
   - Network timeouts or API rate-limit responses automatically trigger up to 2 retries with exponential backoff (`countdown = 60 * (retries + 1)`).
3. **Orphaned Directory Purge Task**:
   - `cleanup_stale_directories_task` runs periodically to detect and delete temporary extraction folders older than 1 hour (`max_age_seconds=3600`).
