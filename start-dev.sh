#!/usr/bin/env sh
# SecureAgent — development mode: backend API + Vite dev server with hot reload.
# (For normal use prefer ./run.sh for the desktop app or ./serve.sh for browser mode.)
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "SecureAgent is not installed yet. Run:  ./install.sh" >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "npm (Node.js) is required for dev mode. Alternatively use browser mode: ./serve.sh" >&2
  exit 1
fi

if ! command -v ollama >/dev/null 2>&1; then
  echo "Warning: Ollama is not installed or not on PATH. The UI and health API will start, but AI calls will be unavailable." >&2
elif ! ollama list >/dev/null 2>&1; then
  echo "Warning: Ollama is not running. Start it with: ollama serve" >&2
fi
if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "Created .env with localhost-only development defaults."
fi
"$ROOT/.venv/bin/python" -m uvicorn app.main:app --app-dir "$ROOT/backend" --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!
trap 'kill "$BACKEND_PID" 2>/dev/null || true' EXIT INT TERM
cd "$ROOT/frontend"
npm run dev
