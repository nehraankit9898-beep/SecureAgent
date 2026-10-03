#!/usr/bin/env bash
# SecureAgent — launch the Electron desktop app (Linux/Debian/Kali).
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "SecureAgent is not installed yet. Run:  ./install.sh" >&2
  exit 1
fi
if [ ! -x "$ROOT/desktop/node_modules/.bin/electron" ]; then
  echo "Desktop shell is not installed (Node/Electron missing). Run:  ./install.sh --desktop" >&2
  echo "Or use browser mode instead:  ./serve.sh" >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  echo "NOTE: running as root — the Electron window will start with --no-sandbox (handled automatically)."
fi

# Point the desktop shell at the project's Python virtual environment.
export SECURE_AGENT_DEV_PYTHON="$ROOT/.venv/bin/python"
# Live here, so data/, logs/ and workspace/ default into the project directory.
cd "$ROOT"

exec "$ROOT/desktop/node_modules/.bin/electron" "$ROOT/desktop" "$@"
