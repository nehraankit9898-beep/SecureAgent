#!/usr/bin/env bash
# SecureAgent — headless / browser mode (no Node.js or Electron required).
# Serves the dashboard and API at http://127.0.0.1:<port> (loopback only).
#
# Usage:  ./serve.sh [port]        (default port: 8000, or SECURE_AGENT_PORT)
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "SecureAgent is not installed yet. Run:  ./install.sh  (or --no-desktop for headless only)" >&2
  exit 1
fi

PORT="${1:-${SECURE_AGENT_PORT:-8000}}"
case "$PORT" in ''|*[!0-9]*|0|*[!0-9]*) echo "Invalid port: $PORT" >&2; exit 1 ;; esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then echo "Port must be 1024–65535" >&2; exit 1; fi

if [ -f "$ROOT/backend/static/index.html" ]; then
  UI="Dashboard:  http://127.0.0.1:$PORT/"
else
  UI="Dashboard:  not built (backend/static missing) — API only at http://127.0.0.1:$PORT/api/v1/health"
fi

# Live here so relative data/, logs/, workspace/ paths from .env resolve correctly.
cd "$ROOT"

echo "SecureAgent headless mode"
echo "  $UI"
echo "  Health:    http://127.0.0.1:$PORT/health"
echo "  Stop with: Ctrl+C"
echo
exec "$ROOT/.venv/bin/python" -m uvicorn app.main:app --app-dir "$ROOT/backend" --host 127.0.0.1 --port "$PORT" --no-server-header
