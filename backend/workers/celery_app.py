from celery import Celery
from core.config import settings
from core.logging_config import logger

celery_app = Celery(
    "securecode_tasks",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=settings.CELERY_TASK_TIMEOUT_SECONDS,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIMEOUT_SECONDS,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    imports=[
        "workers.scan_tasks",
        "workers.cleanup_tasks",
    ],
)
