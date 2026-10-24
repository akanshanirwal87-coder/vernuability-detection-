#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting SecureCode AI (Backend + Frontend)..."

# Start Backend
"$DIR/start_backend.sh" &
BACKEND_PID=$!

sleep 2

# Start Frontend
"$DIR/start_frontend.sh" &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID" SIGINT SIGTERM EXIT
wait

