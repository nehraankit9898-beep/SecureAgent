#!/usr/bin/env bash
# SecureAgent — Linux diagnostics (Debian/Kali/Ubuntu port of diagnose.ps1).
# Writes diagnostic-report.txt next to this script.
set -uo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPORT="$ROOT/diagnostic-report.txt"

pass=0; fail=0
line()  { printf '%s\n' "$1" >> "$REPORT"; }
check() { # name ok value fix
  if [ "$2" -eq 1 ]; then line "[PASS] $1 : $3"; pass=$((pass+1))
  else line "[FAIL] $1 : $3"; [ -n "${4:-}" ] && line "       Recommended fix: $4"; fail=$((fail+1)); fi
}

: > "$REPORT"
line "SecureAgent diagnostic report"
line "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
line "Root: $ROOT"
line ""

# --- OS / architecture -------------------------------------------------------
if [ -r /etc/os-release ]; then . /etc/os-release; line "[INFO] OS: ${PRETTY_NAME:-unknown}"; fi
line "[INFO] Kernel: $(uname -sr), Arch: $(uname -m), Platform: linux"
line ""

check "Required file backend/app/main.py"   $([ -f "$ROOT/backend/app/main.py" ] && echo 1 || echo 0) present "Re-extract the release."
check "Required file frontend/package.json" $([ -f "$ROOT/frontend/package.json" ] && echo 1 || echo 0) present "Re-extract the release."
check "Required file desktop/package.json"  $([ -f "$ROOT/desktop/package.json" ] && echo 1 || echo 0) present "Re-extract the release."
check "Required file install.sh"            $([ -f "$ROOT/install.sh" ] && echo 1 || echo 0) present "Re-extract the release."

# --- python / venv -----------------------------------------------------------
if [ -x "$ROOT/.venv/bin/python" ]; then
  pyver=$("$ROOT/.venv/bin/python" --version 2>&1)
  check "Python virtual environment" 1 "$ROOT/.venv ($pyver)"
else
  check "Python virtual environment" 0 "missing" "Run ./install.sh"
fi
syspy=$(command -v python3 || true)
[ -n "$syspy" ] && check "System Python 3" 1 "$($syspy --version 2>&1)" || check "System Python 3" 0 "not found" "sudo apt install python3 python3-venv"

# --- node / electron ---------------------------------------------------------
if command -v node >/dev/null 2>&1; then check "Node.js" 1 "$(node --version)" ">= 20 needed only for the desktop app"
else check "Node.js" 0 "not installed" "Desktop app needs Node 20+; browser mode works without it"; fi
check "Electron runtime" $([ -x "$ROOT/desktop/node_modules/.bin/electron" ] && echo 1 || echo 0) \
  "$([ -x "$ROOT/desktop/node_modules/.bin/electron" ] && echo installed || echo missing)" "Run ./install.sh --desktop"
check "Dashboard build (backend/static)" $([ -f "$ROOT/backend/static/index.html" ] && echo 1 || echo 0) \
  "$([ -f "$ROOT/backend/static/index.html" ] && echo present || echo missing)" "Run ./install.sh --rebuild-ui"

# --- writable directories ----------------------------------------------------
for dir in data logs workspace; do
  path="$ROOT/$dir"
  if mkdir -p "$path" 2>/dev/null && touch "$path/.write-test" 2>/dev/null && rm -f "$path/.write-test"; then
    check "Writable $dir" 1 "$path"
  else
    check "Writable $dir" 0 "$path" "Check filesystem permissions."
  fi
done

# --- ports -------------------------------------------------------------------
port_busy() {  # 1 if something listens on the port
  if command -v ss >/dev/null 2>&1; then ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$" && return 1 || return 0
  elif command -v netstat >/dev/null 2>&1; then netstat -ltn 2>/dev/null | grep -Eq "[:.]$1[[:space:]]" && return 1 || return 0
  fi
  return 0
}
check "Preferred port 8765" $(port_busy 8765 && echo 0 || echo 1) \
  "$(port_busy 8765 && echo 'occupied; automatic fallback will be used' || echo 'available')"
check "Headless port 8000" $(port_busy 8000 && echo 0 || echo 1) \
  "$(port_busy 8000 && echo occupied || echo available)"

# --- ollama ------------------------------------------------------------------
if command -v ollama >/dev/null 2>&1; then
  if ollama list >/dev/null 2>&1; then check "Ollama (optional)" 1 "$(command -v ollama) — service running"
  else check "Ollama (optional)" 1 "$(command -v ollama) — installed, service not reachable" "Start it with: systemctl --user start ollama  or  ollama serve"; fi
else
  check "Ollama (optional)" 1 "not installed; local core remains available" "Install with: curl -fsSL https://ollama.com/install.sh | sh"
fi

# --- live backend ------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  for port in 8765 8000; do
    body=$(curl -fsS --max-time 2 "http://127.0.0.1:$port/health" 2>/dev/null || true)
    if [ -n "$body" ]; then line "[INFO] Live backend on port $port: $body"; fi
  done
fi

line ""
line "Application data: $ROOT/data"
line "Logs:             $ROOT/logs  and  ~/.config/SecureAgent/logs (desktop mode)"
line "Summary: $pass passed, $fail failed"
printf '%s\n' "Diagnostic report: $REPORT ($pass passed, $fail failed)"
[ "$fail" -eq 0 ] && exit 0 || exit 1
