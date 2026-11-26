import os
import time
import shutil
import glob
from workers.celery_app import celery_app
from core.config import settings
from core.logging_config import logger


@celery_app.task(name="cleanup_stale_directories_task")
def cleanup_stale_directories_task(max_age_seconds: int = 3600) -> int:
    """Cleans up stale repository extraction temporary directories safely."""
    cleaned_count = 0
    now = time.time()
    temp_root = os.path.realpath(settings.TEMP_DIR_ROOT or "/tmp")

    patterns = [
        os.path.join(temp_root, "securecode_repo_*"),
        os.path.join(temp_root, "tmp*securecode*")
    ]

    for pat in patterns:
        for folder in glob.glob(pat):
            if os.path.islink(folder) or not os.path.isdir(folder):
                continue
            resolved = os.path.realpath(folder)
            if not resolved.startswith(temp_root + os.sep):
                continue
            try:
                mtime = os.path.getmtime(resolved)
                if now - mtime > max_age_seconds:
                    shutil.rmtree(resolved, ignore_errors=True)
                    cleaned_count += 1
                    logger.info("Cleaned up stale temp directory: %s", resolved)
            except Exception as e:
                logger.warning("Error inspecting temp folder '%s': %s", folder, str(e))

    return cleaned_count
