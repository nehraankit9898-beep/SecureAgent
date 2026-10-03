# PyInstaller specification for the Linux desktop backend.
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

root = Path(SPECPATH).resolve()
hidden = collect_submodules("app") + collect_submodules("uvicorn") + collect_submodules("pydantic")

a = Analysis(
    [str(root / "desktop_entry.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[(str(root / "static"), "static")],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SecureAgentBackend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
