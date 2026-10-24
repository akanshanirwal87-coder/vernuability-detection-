#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/backend"

if [ -f "$DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$DIR/.venv/bin/python"
elif [ -f "$DIR/backend/.venv/bin/python" ]; then
    PYTHON_BIN="$DIR/backend/.venv/bin/python"
else
    PYTHON_BIN="python3"
fi

echo "Starting FastAPI Backend on http://0.0.0.0:8000 using $PYTHON_BIN..."
exec "$PYTHON_BIN" main.py

