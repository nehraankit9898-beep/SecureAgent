#!/usr/bin/env bash
# SecureAgent — Linux uninstaller (Debian/Kali/Ubuntu).
# Removes the virtual environment, Node modules, and the menu entry.
# User data (database, workspace, logs, .env) is KEPT unless --purge is passed.
#
# Usage:  ./uninstall.sh [--purge]
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "Uninstalling SecureAgent development/runtime files…"

rm -rf "$ROOT/.venv" && echo "  removed .venv (Python environment)"
rm -rf "$ROOT/frontend/node_modules" && echo "  removed frontend/node_modules"
rm -rf "$ROOT/desktop/node_modules" && echo "  removed desktop/node_modules (Electron)"

APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
rm -f "$APP_DIR/secureagent.desktop" && echo "  removed application menu entry"
rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/pixmaps/secureagent.png" 2>/dev/null || true

if [ "$PURGE" -eq 1 ]; then
  rm -rf "$ROOT/data" "$ROOT/logs" "$ROOT/workspace" "$ROOT/.env"
  rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/SecureAgent"
  echo "  PURGE: removed data/, logs/, workspace/, .env and ~/.config/SecureAgent"
else
  echo
  echo "Kept your data: $ROOT/data  $ROOT/workspace  $ROOT/logs  $ROOT/.env"
  echo "Desktop-mode app data: ${XDG_CONFIG_HOME:-$HOME/.config}/SecureAgent"
  echo "Delete permanently with:  ./uninstall.sh --purge"
fi
echo "Done."
