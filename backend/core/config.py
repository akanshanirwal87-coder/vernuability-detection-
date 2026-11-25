import os
import json
from typing import List
from pathlib import Path


def _load_env_file(env_path: Path) -> None:
    """Lightweight .env loader without third-party dependencies."""
    if not env_path.is_file():
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


# Automatically load from repo root or backend/.env
_repo_root = Path(__file__).resolve().parent.parent.parent
_load_env_file(_repo_root / ".env")
_load_env_file(Path(__file__).resolve().parent.parent / ".env")


class Settings:
    """Production configuration and security settings."""

    # Server Configuration
    APP_NAME: str = "SecureCode AI Backend"
    APP_VERSION: str = "2.1.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # Host & Port
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # CORS: Explicitly allowed origins (No wildcards with credentials in production)
    _default_origins = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
    _raw_origins = os.getenv("ALLOWED_ORIGINS", _default_origins)
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() for origin in _raw_origins.split(",") if origin.strip()
    ]

    # JWT Authentication
    JWT_SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY",
        "dev-insecure-secret-key-change-in-production-securecode-ai-2026"
    )
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

    # Admin Security & Retraining Authorization
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    # Pre-computed PBKDF2 hash of default password 'AdminSecure2026!'
    # Format: pbkdf2:sha256:100000$<salt>$<hash>
    ADMIN_PASSWORD_HASH: str = os.getenv(
        "ADMIN_PASSWORD_HASH",
        "pbkdf2:sha256:100000$63c78684c130bf94b3a4dde70fd55543$30b6cd2bb120cef576d969a1a9fc22ff3ba2476334ad520321342156febf58cf"
    )
    ADMIN_API_KEY: str = os.getenv(
        "ADMIN_API_KEY",
        "sec-admin-phase1-production-token-9f82d1c"
    )

    # File Upload Security Restrictions
    MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(5 * 1024 * 1024)))  # 5 MB
    ALLOWED_EXTENSIONS: List[str] = [
        ".py", ".js", ".jsx", ".ts", ".tsx",
        ".json", ".toml", ".txt"
    ]

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

    # Storage & Database
    DB_PATH: str = os.getenv(
        "DB_PATH",
        str(Path(__file__).resolve().parent.parent / "scans.db")
    )
    # PostgreSQL & SQLAlchemy 2.x Database URL
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{Path(__file__).resolve().parent.parent / 'scans.db'}"
    )
    TEST_DATABASE_URL: str = os.getenv(
        "TEST_DATABASE_URL",
        "sqlite:///:memory:"
    )

    # Token Lifespans
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    # GitHub App & OAuth Integration
    GITHUB_APP_ID: str = os.getenv("GITHUB_APP_ID", "")
    GITHUB_APP_PRIVATE_KEY: str = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    GITHUB_APP_PRIVATE_KEY_PATH: str = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    GITHUB_API_BASE_URL: str = os.getenv("GITHUB_API_BASE_URL", "https://api.github.com").rstrip("/")
    _raw_github_hosts = os.getenv("ALLOWED_GITHUB_HOSTS", "github.com,api.github.com")
    ALLOWED_GITHUB_HOSTS: List[str] = [
        h.strip().lower() for h in _raw_github_hosts.split(",") if h.strip()
    ]

    # Repository Ingestion & Sandboxing Limits
    MAX_REPO_ARCHIVE_SIZE_BYTES: int = int(os.getenv("MAX_REPO_ARCHIVE_SIZE_BYTES", str(50 * 1024 * 1024)))  # 50 MB
    MAX_REPO_FILES_COUNT: int = int(os.getenv("MAX_REPO_FILES_COUNT", "1500"))
    MAX_REPO_FILE_SIZE_BYTES: int = int(os.getenv("MAX_REPO_FILE_SIZE_BYTES", str(1 * 1024 * 1024)))  # 1 MB
    REPO_DOWNLOAD_TIMEOUT_SECONDS: int = int(os.getenv("REPO_DOWNLOAD_TIMEOUT_SECONDS", "30"))
    TEMP_DIR_ROOT: str = os.getenv("TEMP_DIR_ROOT", "")

    # Celery & Redis Distributed Processing
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    CELERY_TASK_TIMEOUT_SECONDS: int = int(os.getenv("CELERY_TASK_TIMEOUT_SECONDS", "600"))
    CELERY_TASK_SOFT_TIMEOUT_SECONDS: int = int(os.getenv("CELERY_TASK_SOFT_TIMEOUT_SECONDS", "540"))



settings = Settings()
