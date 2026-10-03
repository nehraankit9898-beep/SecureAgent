#!/usr/bin/env bash
# ============================================================================
# SecureAgent 1.3.4 — Linux (Debian / Kali / Ubuntu) one-click setup
#
# What it does:
#   1. Installs system prerequisites (python3-venv, build tools, optionally Node.js)
#   2. Creates a local Python virtual environment (.venv) and installs the backend
#   3. Builds (or reuses the bundled) frontend dashboard into backend/static
#   4. Installs the Electron desktop shell (optional, requires Node.js)
#   5. Registers an application menu entry (optional desktop mode)
#
# Usage:
#   ./install.sh                 # full install (asks before big downloads)
#   ./install.sh --no-desktop    # headless/browser mode only (Python only)
#   ./install.sh --desktop       # force desktop shell setup (auto-installs Node 22 if missing)
#   ./install.sh --rebuild-ui    # force frontend rebuild even if backend/static exists
#   ./install.sh --with-tests    # install and run backend/frontend/desktop tests
#   ./install.sh --no-ollama     # do not touch or check Ollama at all
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------- helpers ---
BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
log()  { printf '%s\n' "${CYAN}==>${RESET} $*"; }
ok()   { printf '%s\n' "${GREEN} ✔${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW} !${RESET} $*"; }
die()  { printf '%s\n' "${RED} ✘ $*${RESET}" >&2; exit 1; }

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"

DO_DESKTOP="auto"     # auto | yes | no
REBUILD_UI=0
WITH_TESTS=0
NO_OLLAMA=0
for arg in "$@"; do
  case "$arg" in
    --no-desktop) DO_DESKTOP="no" ;;
    --desktop)    DO_DESKTOP="yes" ;;
    --rebuild-ui) REBUILD_UI=1 ;;
    --with-tests) WITH_TESTS=1 ;;
    --no-ollama)  NO_OLLAMA=1 ;;
    -h|--help)    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $arg (try --help)" ;;
  esac
done

INTERACTIVE=0
if [ -t 0 ] && [ -t 1 ]; then INTERACTIVE=1; fi

# ------------------------------------------------------------------ checks --
[ -f "$ROOT/backend/app/main.py" ]  || die "Run this script from the extracted 'source' directory (backend/app/main.py not found)."
APP_REQUIREMENTS="$ROOT/backend/requirements.lock"
DEV_REQUIREMENTS="$ROOT/backend/requirements-dev.lock"
[ -f "$APP_REQUIREMENTS" ] || die "backend/requirements.lock is missing — deterministic installation cannot continue."
[ -f "$DEV_REQUIREMENTS" ] || die "backend/requirements-dev.lock is missing — deterministic test installation cannot continue."

if [ "$(id -u)" -eq 0 ]; then
  warn "Running as root. SecureAgent will still work, but prefer a normal user account."
  SUDO=""
else
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"
  else SUDO=""; warn "sudo not found — system package installation will be skipped if needed."
  fi
fi

detect_py() {  # prints the chosen interpreter, empty if none
  # Spec section 21: support Python 3.11–3.14.
  for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) and sys.version_info < (3, 15) else 1)' 2>/dev/null; then
        echo "$candidate"; return 0
      fi
    fi
  done
}

APT_UPDATED=0
apt_install() {  # best-effort apt install of requested packages
  if ! command -v apt-get >/dev/null 2>&1; then return 1; fi
  if [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then return 1; fi
  if [ "$APT_UPDATED" -eq 0 ]; then
    log "Refreshing apt package index (may take a moment)…"
    $SUDO apt-get update -y >/dev/null 2>&1 || warn "apt-get update failed — continuing with cached index."
    APT_UPDATED=1
  fi
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1
}

node_major() { command -v node >/dev/null 2>&1 || { echo 0; return; }; node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }
npm_major() { command -v npm >/dev/null 2>&1 || { echo 0; return; }; npm --version 2>/dev/null | cut -d. -f1 || echo 0; }

ensure_python() {
  PY=$(detect_py || true)
  if [ -z "${PY:-}" ]; then
    log "No suitable Python 3.11–3.14 found. Trying apt…"
    apt_install python3 python3-venv python3-pip || die "Please install Python 3.11+ (e.g. on Kali: sudo apt install python3 python3-venv) and re-run ./install.sh"
    PY=$(detect_py || true)
    [ -n "$PY" ] || die "Python 3.11–3.14 is required. On Kali/Debian: sudo apt install python3 python3-venv"
  fi
  ok "Using Python: $PY ($($PY --version 2>&1))"

  # ensure venv + pip support (Debian/Kali split python3-venv out)
  if ! "$PY" -m ensurepip --version >/dev/null 2>&1; then
    log "Installing Python venv support (python3-venv / ensurepip)…"
    VENV_PKG=$("$PY" -c 'import sys; print("python%d.%d-venv" % sys.version_info[:2])')
    apt_install "$VENV_PKG" || apt_install python3-venv || \
      warn "Could not auto-install python3-venv. If venv creation fails, run: sudo apt install python3-venv"
  fi

  # Spec section 21: install bubblewrap for the RESTRICTED_AGENT namespace sandbox.
  # This is the preferred sandbox mechanism on Debian/Ubuntu/Kali.
  if ! command -v bwrap >/dev/null 2>&1; then
    log "Installing bubblewrap for the Linux namespace sandbox…"
    apt_install bubblewrap || warn "Could not auto-install bubblewrap. RESTRICTED_AGENT mode will fall back to unshare(1) if available, else report LINUX_SANDBOX_UNAVAILABLE."
  fi
}

ensure_node() {  # only called when desktop mode is needed
  if [ "$(node_major)" -ge 20 ] && [ "$(npm_major)" -ge 9 ]; then
    ok "Node.js $(node --version) and npm $(npm --version) detected."; return 0
  fi
  if [ "$DO_DESKTOP" = "auto" ]; then
    if [ "$INTERACTIVE" -eq 1 ]; then
      printf '%s' "${CYAN}==> Node.js >= 20 is required for the desktop app. Install Node.js 22 now? [Y/n]: ${RESET}"
      read -r answer
      case "$answer" in n*|N*) return 1 ;; esac
    else
      warn "Node.js >= 20 not found — skipping desktop shell (headless mode only). Re-run with: ./install.sh --desktop"
      return 1
    fi
  fi
  log "Installing Node.js 22 (NodeSource)…"
  if command -v apt-get >/dev/null 2>&1 && [ -n "$SUDO" ]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | $SUDO -E bash - >/dev/null 2>&1 || true
    apt_install nodejs || true
  elif command -v apt-get >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1 || true
    apt_install nodejs || true
  fi
  [ "$(node_major)" -ge 20 ] && [ "$(npm_major)" -ge 9 ] || { warn "Node.js >= 20 and npm >= 9 could not be installed automatically — skipping desktop shell."; return 1; }
  ok "Node.js $(node --version) and npm $(npm --version) installed."
}

# ---------------------------------------------------------------- 1. python --
ensure_python

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  log "Creating virtual environment (.venv)…"
  "$PY" -m venv "$ROOT/.venv" || die "venv creation failed. Install python3-venv (sudo apt install python3-venv) and re-run."
else
  ok "Existing virtual environment found."
fi

VPY="$ROOT/.venv/bin/python"
log "Upgrading pip inside the virtual environment…"
"$VPY" -m pip install --upgrade pip >/dev/null 2>&1 || warn "pip upgrade skipped (offline?)."

log "Installing exact backend dependencies from backend/requirements.lock. This can take a few minutes."
"$VPY" -m pip install --prefer-binary -r "$APP_REQUIREMENTS" || die "Backend dependency installation failed — check your internet connection and re-run ./install.sh"
ok "Backend dependencies installed from the lock file."

if [ "$WITH_TESTS" -eq 1 ]; then
  log "Installing test dependencies (pytest)…"
  "$VPY" -m pip install --prefer-binary -r "$DEV_REQUIREMENTS" || die "Test dependency installation failed."
fi

# ---------------------------------------------------------------- 2. config --
[ -f "$ROOT/.env" ] || { cp "$ROOT/.env.example" "$ROOT/.env"; ok "Created .env with localhost-only development defaults."; }
mkdir -p "$ROOT/data" "$ROOT/logs" "$ROOT/workspace"

# ---------------------------------------------------------------- 3. ui ------
NEED_UI_BUILD=1
if [ -f "$ROOT/backend/static/index.html" ] && [ "$REBUILD_UI" -eq 0 ]; then
  NEED_UI_BUILD=0
  ok "Prebuilt dashboard found in backend/static (use --rebuild-ui to rebuild)."
fi
if [ "$NEED_UI_BUILD" -eq 1 ]; then
  if [ "$(node_major)" -ge 20 ]; then
    log "Building dashboard (frontend)…"
    npm --prefix "$ROOT/frontend" ci --no-audit --no-fund >/dev/null 2>&1 || die "frontend npm ci failed."
    npm --prefix "$ROOT/frontend" run build >/dev/null 2>&1 || die "frontend build failed."
    rm -rf "$ROOT/backend/static"; mkdir -p "$ROOT/backend/static"
    cp -r "$ROOT/frontend/dist/." "$ROOT/backend/static/"
    ok "Dashboard built and synced to backend/static."
  else
    warn "Node.js >= 20 missing — cannot rebuild UI. Headless mode still serves the bundled backend/static if present."
  fi
fi

# ---------------------------------------------------------------- 4. desktop -
DESKTOP_READY=0
if [ "$DO_DESKTOP" != "no" ]; then
  if ensure_node; then
    log "Installing Electron desktop shell (downloads the Electron runtime, ~100 MB)…"
    if npm --prefix "$ROOT/desktop" ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; then
      npm --prefix "$ROOT/desktop" rebuild electron >/dev/null 2>&1 || warn "Electron runtime download failed; desktop app may not launch (re-run ./install.sh)."
      DESKTOP_READY=1
      ok "Desktop shell installed."
    else
      warn "desktop npm ci failed — desktop app unavailable; headless mode still works."
    fi
  fi
else
  ok "Desktop shell skipped (--no-desktop). Start headless mode with: ./serve.sh"
fi

# ------------------------------------------------------------ 5. menu entry --
if [ "$DESKTOP_READY" -eq 1 ]; then
  APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
  PIXMAP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/pixmaps"
  mkdir -p "$APP_DIR" "$PIXMAP_DIR"
  cp -f "$ROOT/desktop/assets/icon.png" "$PIXMAP_DIR/secureagent.png" 2>/dev/null || true
  cat > "$APP_DIR/secureagent.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=SecureAgent
Comment=Local-first SecureAgent desktop app
Exec=$ROOT/run.sh
Path=$ROOT
Icon=secureagent
Terminal=false
Categories=Utility;Development;
EOF
  if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true; fi
  ok "Application menu entry created (SecureAgent)."
fi

# ---------------------------------------------------------------- 6. ollama --
if [ "$NO_OLLAMA" -eq 0 ]; then
  if command -v ollama >/dev/null 2>&1; then
    ok "Ollama detected: $(command -v ollama)"
    if command -v systemctl >/dev/null 2>&1 && ! ollama list >/dev/null 2>&1; then
      log "Starting Ollama service (systemd)…"
      $SUDO systemctl enable --now ollama >/dev/null 2>&1 || warn "Could not auto-start ollama.service — run it manually with: ollama serve"
    fi
  else
    warn "Ollama is not installed. Generative chat and Knowledge/RAG will report OLLAMA_SERVICE_STOPPED."
    echo "    Administrator action (official installer): curl -fsSL https://ollama.com/install.sh | sh"
  fi
fi

# ---------------------------------------------------------- 7. dependencies --
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then ok "Docker daemon is available."
  else warn "Docker CLI is installed but the daemon is unavailable; sandboxed execution remains disabled."; fi
else
  warn "Docker is not installed; Terminal, Python, and test sandboxes remain disabled."
fi

# ------------------------------------------------ 7b. linux sandbox detection --
# SecureAgent 1.3.4+ runs the RESTRICTED_AGENT terminal inside a Linux
# namespace sandbox. We need either bubblewrap (preferred) or unprivileged
# user namespaces (fallback). If neither is available, autonomous terminal
# execution stays disabled with LINUX_SANDBOX_UNAVAILABLE.
SANDBOX_MECHANISM="none"
if command -v bwrap >/dev/null 2>&1; then
  SANDBOX_MECHANISM="bubblewrap"
  ok "Bubblewrap (bwrap) detected — RESTRICTED_AGENT mode will use a mount+user+pid+net namespace sandbox."
elif command -v firejail >/dev/null 2>&1; then
  SANDBOX_MECHANISM="firejail"
  ok "Firejail detected — RESTRICTED_AGENT mode will use firejail isolation."
elif command -v unshare >/dev/null 2>&1; then
  if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
    UNS=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
    if [ "$UNS" = "1" ] || [ "$UNS" = "y" ]; then
      if unshare --user --pid --net --fork --map-user=65534 --map-group=65534 -- echo "userns_probe_ok" >/dev/null 2>&1; then
        SANDBOX_MECHANISM="linux-user-namespace"
        ok "Unprivileged user namespaces available — RESTRICTED_AGENT mode will use unshare(1) with uid remapping."
      else
        warn "unshare(1) is present but could not create a user namespace. RESTRICTED_AGENT mode will report LINUX_SANDBOX_UNAVAILABLE."
        echo "    Fix: install bubblewrap —  sudo apt install bubblewrap"
      fi
    else
      warn "Unprivileged user namespaces are disabled in the kernel (/proc/sys/kernel/unprivileged_userns_clone=$UNS)."
      echo "    Fix: echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone"
      echo "    Or install bubblewrap:  sudo apt install bubblewrap"
    fi
  else
    # Sysctl absent — kernel default usually allows userns. Probe directly.
    if unshare --user --pid --net --fork --map-user=65534 --map-group=65534 -- echo "userns_probe_ok" >/dev/null 2>&1; then
      SANDBOX_MECHANISM="linux-user-namespace"
      ok "Unprivileged user namespaces available — RESTRICTED_AGENT mode will use unshare(1) with uid remapping."
    else
      warn "unshare(1) is present but could not create a user namespace. Install bubblewrap:  sudo apt install bubblewrap"
    fi
  fi
else
  warn "Neither bubblewrap, firejail, nor unshare(1) is available."
  echo "    RESTRICTED_AGENT mode will report LINUX_SANDBOX_UNAVAILABLE and refuse autonomous terminal execution."
  echo "    Install bubblewrap:  sudo apt install bubblewrap"
fi
export SECURE_AGENT_SANDBOX_MECHANISM="$SANDBOX_MECHANISM"

# Detect Python/Node/Git toolchain versions for the system info panel.
log "Toolchain versions:"
PY_VER=$("$PY" --version 2>&1 | head -1); echo "    $PY_VER"
if command -v node >/dev/null 2>&1; then echo "    Node.js $(node --version)"; fi
if command -v git >/dev/null 2>&1; then echo "    Git $(git --version)"; fi
if command -v docker >/dev/null 2>&1; then echo "    Docker $(docker --version 2>&1 | head -1)"; fi
if command -v ollama >/dev/null 2>&1; then echo "    Ollama $(ollama --version 2>&1 | head -1)"; fi

# ---------------------------------------------------------- 8. verification --
log "Starting a temporary loopback backend for installation verification…"
VERIFY_PORT=$("$VPY" - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
VERIFY_LOG="$ROOT/logs/install-health.log"
PYTHONPATH="$ROOT/backend" "$VPY" -m uvicorn app.main:app --host 127.0.0.1 --port "$VERIFY_PORT" --no-server-header >"$VERIFY_LOG" 2>&1 &
VERIFY_PID=$!
cleanup_verify() { kill "$VERIFY_PID" >/dev/null 2>&1 || true; wait "$VERIFY_PID" >/dev/null 2>&1 || true; }
trap cleanup_verify EXIT
HEALTH_OK=0
for _ in $(seq 1 40); do
  if "$VPY" - "$VERIFY_PORT" <<'PY' >/dev/null 2>&1
import json, sys, urllib.request
with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/v1/health", timeout=2) as response:
    body = json.load(response)
assert response.status == 200 and body["backend"] == "ok" and body["database"] == "ok"
PY
  then HEALTH_OK=1; break; fi
  sleep .25
done
[ "$HEALTH_OK" -eq 1 ] || die "Backend health verification failed. See $VERIFY_LOG"
ok "Backend started and /api/v1/health returned a valid response."
cleanup_verify
trap - EXIT

if [ "$WITH_TESTS" -eq 1 ]; then
  log "Running backend regression tests…"
  PYTHONPATH="$ROOT/backend" "$VPY" -m pytest -q || die "Backend tests failed."
  if [ "$(node_major)" -ge 20 ] && [ "$(npm_major)" -ge 9 ]; then
    log "Running frontend tests and production build…"
    npm --prefix "$ROOT/frontend" ci --no-audit --no-fund >/dev/null
    npm --prefix "$ROOT/frontend" test
    npm --prefix "$ROOT/frontend" run build
    log "Running Electron integration tests…"
    npm --prefix "$ROOT/desktop" ci --ignore-scripts --no-audit --no-fund >/dev/null
    npm --prefix "$ROOT/desktop" test
  else
    die "--with-tests requires Node.js >= 20 and npm >= 9 for frontend/Electron validation."
  fi
  ok "All installed test suites passed."
fi

# ---------------------------------------------------------------- summary ----
echo
echo "${BOLD}SecureAgent setup complete.${RESET}"
echo "  ${CYAN}Desktop app:${RESET}  ./run.sh        (Electron window; needs the desktop shell installed)"
echo "  ${CYAN}Browser mode:${RESET} ./serve.sh      (no Node/Electron needed — opens at http://127.0.0.1:8000)"
echo "  ${CYAN}Diagnostics:${RESET}  ./diagnose.sh   ${CYAN}Uninstall:${RESET} ./uninstall.sh"
[ -f "$ROOT/backend/static/index.html" ] || echo "  ${YELLOW}Note: no dashboard UI present — browser mode will serve API only until you build the UI.${RESET}"
echo
