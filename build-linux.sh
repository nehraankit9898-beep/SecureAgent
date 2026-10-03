#!/usr/bin/env bash
# SecureAgent — build Linux packages (AppImage / .deb / .tar.gz).
#
# Produces:
#   build/backend-build/SecureAgentBackend            (PyInstaller frozen backend)
#   build/electron-build/SecureAgent-<version>-amd64.AppImage / .deb / .tar.gz
#     (<version> comes from desktop/package.json via electron-builder)
#
# Prerequisites: ./install.sh --desktop has completed successfully.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"

[ -x "$ROOT/.venv/bin/python" ] || { echo "Run ./install.sh first." >&2; exit 1; }
[ -x "$ROOT/desktop/node_modules/.bin/electron" ] || { echo "Desktop shell missing — run: ./install.sh --desktop" >&2; exit 1; }
[ -f "$ROOT/backend/static/index.html" ] || { echo "Dashboard missing — run: ./install.sh --rebuild-ui" >&2; exit 1; }

mkdir -p "$ROOT/build"

# 1. Freeze the backend with PyInstaller (uses backend/SecureAgentBackend.spec).
if ! "$ROOT/.venv/bin/python" -c 'import PyInstaller' >/dev/null 2>&1; then
  echo "==> Installing PyInstaller…"
  "$ROOT/.venv/bin/python" -m pip install --prefer-binary "pyinstaller>=6.10,<7" >/dev/null
fi
echo "==> Building frozen backend (SecureAgentBackend)…"
"$ROOT/.venv/bin/python" -m PyInstaller --noconfirm --clean \
  --distpath "$ROOT/build/backend-build" \
  --workpath "$ROOT/build/pyinstaller-work" \
  "$ROOT/backend/SecureAgentBackend.spec"
"$ROOT/.venv/bin/python" "$ROOT/backend/scripts/binary_smoke.py" \
  "$ROOT/build/backend-build/SecureAgentBackend"

# 2. Package the Electron shell for Linux.
echo "==> Building Linux packages (AppImage, deb, tar.gz)…"
npm --prefix "$ROOT/desktop" run dist

echo
echo "Done. Artifacts:"
ls -1 "$ROOT/build/electron-build" 2>/dev/null | sed 's/^/  build\/electron-build\//'
ls -1 "$ROOT/build/backend-build"  2>/dev/null | sed 's/^/  build\/backend-build\//'
