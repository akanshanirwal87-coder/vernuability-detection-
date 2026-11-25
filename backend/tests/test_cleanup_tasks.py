import os
import time
import tempfile
import pytest

from workers.cleanup_tasks import cleanup_stale_directories_task
from core.config import settings


def test_cleanup_stale_directories(monkeypatch):
    """Test that cleanup task purges directories older than max_age_seconds and leaves newer ones."""
    with tempfile.TemporaryDirectory() as base_temp:
        monkeypatch.setattr(settings, "TEMP_DIR_ROOT", base_temp)

        # 1. Create a stale directory
        stale_dir = os.path.join(base_temp, "securecode_repo_stale_123")
        os.makedirs(stale_dir, exist_ok=True)
        # Modify mtime to 2 hours ago
        two_hours_ago = time.time() - 7200
        os.utime(stale_dir, (two_hours_ago, two_hours_ago))

        # 2. Create a fresh directory
        fresh_dir = os.path.join(base_temp, "securecode_repo_fresh_456")
        os.makedirs(fresh_dir, exist_ok=True)

        # Execute cleanup task with 1-hour max age
        cleaned = cleanup_stale_directories_task(max_age_seconds=3600)

        assert cleaned == 1
        assert not os.path.exists(stale_dir)
        assert os.path.exists(fresh_dir)
