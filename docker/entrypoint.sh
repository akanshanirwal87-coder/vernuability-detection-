#!/usr/bin/env bash
set -e

echo "[SecureCode AI] Initializing container startup..."

# Wait for PostgreSQL if DATABASE_URL indicates postgres
if [[ "${DATABASE_URL}" == postgresql* ]] || [[ "${DATABASE_URL}" == postgres* ]]; then
    echo "[SecureCode AI] Waiting for PostgreSQL database connection..."
    python - << 'EOF'
import os
import sys
import time
from urllib.parse import urlparse
import socket

db_url = os.environ.get("DATABASE_URL", "")
try:
    parsed = urlparse(db_url)
    host = parsed.hostname or "db"
    port = parsed.port or 5432
    deadline = time.time() + 30
    connected = False
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                connected = True
                print(f"[SecureCode AI] Connected to database at {host}:{port}")
                break
        except (socket.error, OSError):
            time.sleep(1)
    if not connected:
        print(f"[SecureCode AI] Warning: Timed out waiting for database at {host}:{port}. Proceeding anyway...")
except Exception as e:
    print(f"[SecureCode AI] Database parse check skipped: {e}")
EOF
fi

# Execute database migrations if alembic configuration is present
if [ -f "/app/backend/alembic.ini" ]; then
    echo "[SecureCode AI] Running database migrations (alembic upgrade head)..."
    alembic -c /app/backend/alembic.ini upgrade head || {
        echo "[SecureCode AI] Warning: Alembic migrations encountered an issue or database is already up-to-date."
    }
fi

echo "[SecureCode AI] Startup checks complete. Starting target command: $@"
exec "$@"
