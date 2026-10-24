#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/frontend"

echo "Starting React + Vite Frontend on http://localhost:5173..."
exec npm run dev

