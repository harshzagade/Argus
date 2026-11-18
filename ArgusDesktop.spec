# PyInstaller recipe for the Argus Windows desktop app.
# Build with:  build_windows.bat
# (or:  pyinstaller --noconfirm --clean ArgusDesktop.spec)
# Output: a dist\Argus folder with Argus.exe (one-folder build).

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)

# Data files the server reads from disk at runtime: the dashboard web
# files, the detection rules, and the SOAR playbooks.
datas = [
    (str(ROOT / "dashboard"), "dashboard"),
    (str(ROOT / "rules"), "rules"),
    (str(ROOT / "playbooks"), "playbooks"),
]

# Packages PyInstaller's static analysis cannot see: uvicorn loads its
# pieces dynamically, webview picks a backend at runtime, and the server
# and threat-intel packages are imported by dotted string.
hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("webview")
    + collect_submodules("server")
    + collect_submodules("threatintel")
)

a = Analysis(
    ["desktop_app.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Argus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="Argus",
)
