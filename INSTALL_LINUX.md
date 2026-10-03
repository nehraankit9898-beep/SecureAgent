# SecureAgent 1.3.4 — Linux Installation (Debian / Kali / Ubuntu)

SecureAgent now runs natively on Debian, Kali Rolling, Ubuntu, and derivatives
in two modes:

| Mode | Command | Needs |
|---|---|---|
| **Desktop app** (Electron window) | `./run.sh` | Python 3.11–3.14 + Node.js ≥ 20 |
| **Browser mode** (headless) | `./serve.sh` | Python 3.11–3.14 only |

Both modes talk to the same FastAPI backend on `127.0.0.1`; nothing is exposed
to the network. The backend serves the prebuilt dashboard at
`http://127.0.0.1:8000/` in browser mode.

---

## Quick start (one command)

Extract the archive, then from the `source/` directory:

```bash
chmod +x install.sh
./install.sh
```

The installer:

1. Checks for Python 3.11–3.14 and installs `python3-venv` via apt if missing.
2. Creates a `.venv` and installs backend dependencies (FastAPI, Uvicorn, pypdf, python-docx).
3. Reuses the **prebuilt dashboard** already bundled in `backend/static`
   (pass `--rebuild-ui` to rebuild the React UI from source).
4. Installs the Electron desktop shell if Node.js ≥ 20 is present. Without
   Node.js it finishes in headless-only mode and tells you how to enable desktop later.
5. Creates the application menu entry ("SecureAgent") when desktop mode is installed.
6. Detects Ollama and, on systemd systems, best-effort starts `ollama.service`.

Installer options:

```bash
./install.sh --no-desktop     # headless/browser mode only, never touches Node.js
./install.sh --desktop        # force desktop setup, auto-installs Node 22 via NodeSource
./install.sh --rebuild-ui     # force a fresh frontend build
./install.sh --with-tests     # install pytest and run the backend test suite
./install.sh --no-ollama      # skip every Ollama check
```

## Daily use

```bash
./run.sh          # desktop window (Electron)
./serve.sh        # browser mode at http://127.0.0.1:8000  (Ctrl+C to stop)
./serve.sh 8080   # custom port
./diagnose.sh     # writes diagnostic-report.txt
./uninstall.sh    # removes venv/node_modules/menu entry, keeps your data
./uninstall.sh --purge   # also deletes data/, logs/, workspace/, .env
```

In desktop mode your data lives in `~/.config/SecureAgent/{config,data,logs,workspace}`;
in browser mode it lives in the project's `data/`, `logs/`, and `workspace/`
directories. `start-dev.sh` remains available for hot-reload frontend development.

## Ollama (optional AI chat)

The dashboard works without Ollama (built-in deterministic local core). To
enable generative chat and embeddings:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama pull nomic-embed-text
```

The Linux installer/diagnostics mirror the Windows flow: Setup AI opens
`https://ollama.com/download/linux`, and models can be installed from the
app's setup wizard or Settings screen.

## Requirements

- Debian 12+, Kali Rolling, Ubuntu 22.04+, or any systemd distro with apt
- Python 3.11, 3.12, 3.13, or 3.14 (`python3.13` preferred when available)
- Node.js ≥ 20 **only** for the desktop shell or rebuilding the UI
- ~600 MB disk for dependencies; 4 GB RAM recommended

## Troubleshooting

- **Kali root session:** Electron windows start with `--no-sandbox`
  automatically when running as root (handled inside `desktop/main.js`).
  Prefer a normal user account for daily use.
- **`venv creation failed`:** run `sudo apt install python3-venv` and re-run `./install.sh`.
- **Debian 12 (Python 3.11):** fully supported — the release pin was relaxed
  from `>=3.13` to `>=3.11` for the Linux port.
- **Desktop window does not open:** run `./diagnose.sh`, check
  `desktop/node_modules/.bin/electron` exists, or re-run `./install.sh --desktop`.
  On exotic compositors try `SECURE_AGENT_ELECTRON_NO_SANDBOX=1 ./run.sh`.
- **Port already in use:** the desktop shell auto-falls-back from 8765;
  browser mode accepts a port argument (`./serve.sh 8080`).
- **Corporate proxies / offline:** pre-seed pip's cache or install
  `backend/requirements.txt` into `.venv` manually before re-running the installer.

## Building distributable Linux packages (optional)

To produce an AppImage / `.deb` / `.tar.gz` installer with a frozen backend:

```bash
./install.sh --desktop     # once
./build-linux.sh
# → build/electron-build/SecureAgent-1.3.4-amd64.AppImage (+ .deb, .tar.gz)
```

## Security notes

Unchanged from the Windows release: loopback-only binding, ephemeral bearer
token between the Electron shell and backend, fail-closed network policy,
workspace-confinement for file tools, and approval gates for high-risk
operations. The Linux port does not weaken any of these guarantees — see
`SECURITY.md` for the full model.
