#!/usr/bin/env bash
# =============================================================================
# SoC Security Analyzer - Server Launcher Script
# Starts or restarts the modular FastAPI web server on port 8080.
# =============================================================================

set -e

PORT=8080
HOST="0.0.0.0"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

# Detect Python interpreter
if [ -f "/home/hackdac/.HACK_AI/bin/python3" ]; then
    PYTHON="/home/hackdac/.HACK_AI/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    echo "[ERROR] Python 3 interpreter not found."
    exit 1
fi

echo "=========================================================="
echo " Starting SoC Security Analyzer Server"
echo " Working Dir: $DIR"
echo " Python:      $PYTHON"
echo " Host:        $HOST"
echo " Port:        $PORT"
echo "=========================================================="

# Check if port 8080 is already held by another process
EXISTING_PID=$(lsof -ti :$PORT 2>/dev/null || true)
if [ -n "$EXISTING_PID" ]; then
    echo "[INFO] Found existing process(es) on port $PORT: $EXISTING_PID"
    echo "[INFO] Terminating old process(es)..."
    kill -9 $EXISTING_PID 2>/dev/null || true
    sleep 1
fi

# Ensure GUI assets are built
if [ ! -d "gui/dist" ] || [ ! -f "gui/dist/index.html" ]; then
    echo "[INFO] GUI build not found. Building frontend..."
    (cd gui && npm run build)
fi

echo "[INFO] Launching FastAPI server on http://localhost:$PORT ..."
exec "$PYTHON" -m uvicorn soc_analyzer.dashboard.server:app --host "$HOST" --port "$PORT" --reload
